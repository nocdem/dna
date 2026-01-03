/**
 * @file gsk.c
 * @brief Group Symmetric Key (GSK) Manager Implementation
 *
 * Manages AES-256 symmetric keys for group messaging encryption.
 *
 * Part of DNA Messenger v0.09 - GSK Upgrade
 *
 * @date 2025-11-21
 */

#include "gsk.h"
#include "gsk_packet.h"
#include "gsk_encryption.h"
#include "../message_backup.h"
#include "../crypto/utils/qgp_random.h"
#include "../crypto/utils/qgp_sha3.h"
#include "../crypto/utils/qgp_platform.h"
#include "../dht/core/dht_context.h"
#include "../dht/core/dht_keyserver.h"
#include "../dht/shared/dht_groups.h"
#include "../dht/shared/dht_gsk_storage.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "MSG_GSK"

// Database handle (set during gsk_init)
static sqlite3 *msg_db = NULL;

// KEM keys for GSK encryption (set via gsk_set_kem_keys)
static uint8_t *gsk_kem_pubkey = NULL;   // 1568 bytes (Kyber1024)
static uint8_t *gsk_kem_privkey = NULL;  // 3168 bytes (Kyber1024)

/**
 * Generate a new random GSK for a group
 */
int gsk_generate(const char *group_uuid, uint32_t version, uint8_t gsk_out[GSK_KEY_SIZE]) {
    if (!group_uuid || !gsk_out) {
        QGP_LOG_ERROR(LOG_TAG, "gsk_generate: NULL parameter\n");
        return -1;
    }

    // Generate 32 random bytes for AES-256 key
    if (qgp_randombytes(gsk_out, GSK_KEY_SIZE) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate random GSK\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Generated GSK for group %s v%u\n", group_uuid, version);
    return 0;
}

/**
 * Store GSK in local database (encrypted with Kyber1024 KEM)
 */
int gsk_store(const char *group_uuid, uint32_t version, const uint8_t gsk[GSK_KEY_SIZE]) {
    if (!group_uuid || !gsk) {
        QGP_LOG_ERROR(LOG_TAG, "gsk_store: NULL parameter\n");
        return -1;
    }

    if (!msg_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!gsk_kem_pubkey) {
        QGP_LOG_ERROR(LOG_TAG, "KEM keys not set - call gsk_set_kem_keys() first\n");
        return -1;
    }

    /* Encrypt GSK with Kyber1024 KEM + AES-256-GCM */
    uint8_t encrypted_gsk[GSK_ENC_TOTAL_SIZE];
    if (gsk_encrypt(gsk, gsk_kem_pubkey, encrypted_gsk) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to encrypt GSK\n");
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);
    uint64_t expires_at = now + GSK_DEFAULT_EXPIRY;

    const char *sql = "INSERT OR REPLACE INTO dht_group_gsks "
                      "(group_uuid, gsk_version, gsk_key, created_at, expires_at) "
                      "VALUES (?, ?, ?, ?, ?)";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(msg_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(msg_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, (int)version);
    sqlite3_bind_blob(stmt, 3, encrypted_gsk, GSK_ENC_TOTAL_SIZE, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)now);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)expires_at);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to store GSK: %s\n", sqlite3_errmsg(msg_db));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Stored encrypted GSK for group %s v%u (expires in %d days)\n",
           group_uuid, version, GSK_DEFAULT_EXPIRY / (24 * 3600));
    return 0;
}

/**
 * Load GSK from local database by version (decrypted with Kyber1024 KEM)
 */
int gsk_load(const char *group_uuid, uint32_t version, uint8_t gsk_out[GSK_KEY_SIZE]) {
    if (!group_uuid || !gsk_out) {
        QGP_LOG_ERROR(LOG_TAG, "gsk_load: NULL parameter\n");
        return -1;
    }

    if (!msg_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!gsk_kem_privkey) {
        QGP_LOG_ERROR(LOG_TAG, "KEM keys not set - call gsk_set_kem_keys() first\n");
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);

    const char *sql = "SELECT gsk_key FROM dht_group_gsks "
                      "WHERE group_uuid = ? AND gsk_version = ? AND expires_at > ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(msg_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(msg_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, (int)version);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)now);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const void *blob = sqlite3_column_blob(stmt, 0);
        int blob_size = sqlite3_column_bytes(stmt, 0);

        /* Decrypt encrypted GSK */
        if (gsk_decrypt((const uint8_t *)blob, (size_t)blob_size, gsk_kem_privkey, gsk_out) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to decrypt GSK for group %s v%u\n", group_uuid, version);
            sqlite3_finalize(stmt);
            return -1;
        }

        sqlite3_finalize(stmt);

        QGP_LOG_INFO(LOG_TAG, "Loaded and decrypted GSK for group %s v%u\n", group_uuid, version);
        return 0;
    }

    sqlite3_finalize(stmt);

    if (rc == SQLITE_DONE) {
        QGP_LOG_INFO(LOG_TAG, "No active GSK found for group %s v%u\n", group_uuid, version);
    } else {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load GSK: %s\n", sqlite3_errmsg(msg_db));
    }

    return -1;
}

/**
 * Load active (latest non-expired) GSK from local database (decrypted with Kyber1024 KEM)
 */
int gsk_load_active(const char *group_uuid, uint8_t gsk_out[GSK_KEY_SIZE], uint32_t *version_out) {
    if (!group_uuid || !gsk_out) {
        QGP_LOG_ERROR(LOG_TAG, "gsk_load_active: NULL parameter\n");
        return -1;
    }

    if (!msg_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!gsk_kem_privkey) {
        QGP_LOG_ERROR(LOG_TAG, "KEM keys not set - call gsk_set_kem_keys() first\n");
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);

    const char *sql = "SELECT gsk_key, gsk_version FROM dht_group_gsks "
                      "WHERE group_uuid = ? AND expires_at > ? "
                      "ORDER BY gsk_version DESC LIMIT 1";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(msg_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(msg_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)now);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const void *blob = sqlite3_column_blob(stmt, 0);
        int blob_size = sqlite3_column_bytes(stmt, 0);
        uint32_t version = (uint32_t)sqlite3_column_int(stmt, 1);

        /* Decrypt encrypted GSK */
        if (gsk_decrypt((const uint8_t *)blob, (size_t)blob_size, gsk_kem_privkey, gsk_out) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to decrypt active GSK for group %s\n", group_uuid);
            sqlite3_finalize(stmt);
            return -1;
        }

        if (version_out) {
            *version_out = version;
        }

        sqlite3_finalize(stmt);

        QGP_LOG_INFO(LOG_TAG, "Loaded and decrypted active GSK for group %s v%u\n", group_uuid, version);
        return 0;
    }

    sqlite3_finalize(stmt);

    if (rc == SQLITE_DONE) {
        QGP_LOG_INFO(LOG_TAG, "No active GSK found for group %s\n", group_uuid);
    } else {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load active GSK: %s\n", sqlite3_errmsg(msg_db));
    }

    return -1;
}

/**
 * Rotate GSK (increment version, generate new key)
 */
int gsk_rotate(const char *group_uuid, uint32_t *new_version_out, uint8_t new_gsk_out[GSK_KEY_SIZE]) {
    if (!group_uuid || !new_version_out || !new_gsk_out) {
        QGP_LOG_ERROR(LOG_TAG, "gsk_rotate: NULL parameter\n");
        return -1;
    }

    // Get current version
    uint32_t current_version = 0;
    int rc = gsk_get_current_version(group_uuid, &current_version);
    if (rc != 0) {
        // No existing GSK, start at version 0
        current_version = 0;
        QGP_LOG_INFO(LOG_TAG, "No existing GSK found, starting at version 0\n");
    }

    uint32_t new_version = current_version + 1;

    // Generate new GSK
    rc = gsk_generate(group_uuid, new_version, new_gsk_out);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate new GSK\n");
        return -1;
    }

    *new_version_out = new_version;

    QGP_LOG_INFO(LOG_TAG, "Rotated GSK for group %s: v%u -> v%u\n",
           group_uuid, current_version, new_version);
    return 0;
}

/**
 * Get current GSK version from local database
 */
int gsk_get_current_version(const char *group_uuid, uint32_t *version_out) {
    if (!group_uuid || !version_out) {
        QGP_LOG_ERROR(LOG_TAG, "gsk_get_current_version: NULL parameter\n");
        return -1;
    }

    if (!msg_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    const char *sql = "SELECT MAX(gsk_version) FROM dht_group_gsks WHERE group_uuid = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(msg_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(msg_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        if (sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
            *version_out = (uint32_t)sqlite3_column_int(stmt, 0);
            sqlite3_finalize(stmt);
            return 0;
        } else {
            // No GSK exists for this group
            *version_out = 0;
            sqlite3_finalize(stmt);
            return -1;
        }
    }

    sqlite3_finalize(stmt);
    QGP_LOG_ERROR(LOG_TAG, "Failed to get current version: %s\n", sqlite3_errmsg(msg_db));
    return -1;
}

/**
 * Delete expired GSKs from database
 */
int gsk_cleanup_expired(void) {
    if (!msg_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);

    const char *sql = "DELETE FROM dht_group_gsks WHERE expires_at <= ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(msg_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(msg_db));
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)now);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to cleanup expired GSKs: %s\n", sqlite3_errmsg(msg_db));
        return -1;
    }

    int deleted = sqlite3_changes(msg_db);
    if (deleted > 0) {
        QGP_LOG_INFO(LOG_TAG, "Cleaned up %d expired GSK entries\n", deleted);
    }

    return deleted;
}

/**
 * Initialize GSK subsystem
 */
int gsk_init(void *backup_ctx) {
    if (!backup_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "backup_ctx is NULL\n");
        return -1;
    }

    // Get database handle from backup context
    msg_db = (sqlite3 *)message_backup_get_db(backup_ctx);
    if (!msg_db) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get database handle from backup context\n");
        return -1;
    }

    // Create dht_group_gsks table
    const char *create_table =
        "CREATE TABLE IF NOT EXISTS dht_group_gsks ("
        "  group_uuid TEXT NOT NULL,"
        "  gsk_version INTEGER NOT NULL,"
        "  gsk_key BLOB NOT NULL,"
        "  created_at INTEGER NOT NULL,"
        "  expires_at INTEGER NOT NULL,"
        "  PRIMARY KEY (group_uuid, gsk_version)"
        ")";

    char *err_msg = NULL;
    int rc = sqlite3_exec(msg_db, create_table, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create dht_group_gsks table: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    // Create index for fast lookups
    const char *create_index =
        "CREATE INDEX IF NOT EXISTS idx_gsk_active "
        "ON dht_group_gsks(group_uuid, gsk_version DESC)";

    rc = sqlite3_exec(msg_db, create_index, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create index: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Initialized GSK subsystem\n");

    // Cleanup expired entries on startup
    gsk_cleanup_expired();

    return 0;
}

/**
 * Set KEM keys for GSK encryption/decryption
 */
int gsk_set_kem_keys(const uint8_t *kem_pubkey, const uint8_t *kem_privkey) {
    if (!kem_pubkey || !kem_privkey) {
        QGP_LOG_ERROR(LOG_TAG, "gsk_set_kem_keys: NULL parameter\n");
        return -1;
    }

    /* Clear existing keys if any */
    gsk_clear_kem_keys();

    /* Allocate and copy public key (1568 bytes) */
    gsk_kem_pubkey = malloc(1568);
    if (!gsk_kem_pubkey) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate KEM pubkey\n");
        return -1;
    }
    memcpy(gsk_kem_pubkey, kem_pubkey, 1568);

    /* Allocate and copy private key (3168 bytes) */
    gsk_kem_privkey = malloc(3168);
    if (!gsk_kem_privkey) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate KEM privkey\n");
        qgp_secure_memzero(gsk_kem_pubkey, 1568);
        free(gsk_kem_pubkey);
        gsk_kem_pubkey = NULL;
        return -1;
    }
    memcpy(gsk_kem_privkey, kem_privkey, 3168);

    QGP_LOG_INFO(LOG_TAG, "KEM keys set for GSK encryption\n");
    return 0;
}

/**
 * Clear KEM keys from GSK subsystem
 */
void gsk_clear_kem_keys(void) {
    if (gsk_kem_pubkey) {
        qgp_secure_memzero(gsk_kem_pubkey, 1568);
        free(gsk_kem_pubkey);
        gsk_kem_pubkey = NULL;
    }
    if (gsk_kem_privkey) {
        qgp_secure_memzero(gsk_kem_privkey, 3168);
        free(gsk_kem_privkey);
        gsk_kem_privkey = NULL;
    }
    QGP_LOG_DEBUG(LOG_TAG, "KEM keys cleared\n");
}

/**
 * Helper: Rotate GSK and publish to DHT
 *
 * Common logic for both member add/remove operations.
 */
static int gsk_rotate_and_publish(dht_context_t *dht_ctx, const char *group_uuid, const char *owner_identity) {
    if (!dht_ctx || !group_uuid || !owner_identity) {
        QGP_LOG_ERROR(LOG_TAG, "gsk_rotate_and_publish: NULL parameter\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Rotating GSK for group %s (owner=%s)\n", group_uuid, owner_identity);

    // Step 1: Rotate GSK (increment version, generate new key)
    uint32_t new_version = 0;
    uint8_t new_gsk[GSK_KEY_SIZE];
    if (gsk_rotate(group_uuid, &new_version, new_gsk) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to rotate GSK\n");
        return -1;
    }

    // Step 2: Store new GSK locally
    if (gsk_store(group_uuid, new_version, new_gsk) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to store new GSK\n");
        return -1;
    }

    // Step 3: Get group metadata (members list)
    dht_group_metadata_t *meta = NULL;
    if (dht_groups_get(dht_ctx, group_uuid, &meta) != 0 || !meta) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get group metadata\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Building Initial Key Packet for %u members\n", meta->member_count);

    // Step 4: Fetch Kyber pubkeys for all members
    gsk_member_entry_t *member_entries = (gsk_member_entry_t *)calloc(meta->member_count, sizeof(gsk_member_entry_t));
    if (!member_entries) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate member entries\n");
        dht_groups_free_metadata(meta);
        return -1;
    }

    uint8_t **kyber_pubkeys = (uint8_t **)calloc(meta->member_count, sizeof(uint8_t *));
    if (!kyber_pubkeys) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate kyber pubkey array\n");
        free(member_entries);
        dht_groups_free_metadata(meta);
        return -1;
    }

    size_t valid_members = 0;
    for (uint32_t i = 0; i < meta->member_count; i++) {
        const char *member_identity = meta->members[i];

        // Lookup member's public keys from DHT keyserver
        dna_unified_identity_t *member_id = NULL;
        if (dht_keyserver_lookup(dht_ctx, member_identity, &member_id) != 0 || !member_id) {
            QGP_LOG_ERROR(LOG_TAG, "Warning: Failed to lookup keys for %s (skipping)\n", member_identity);
            continue;
        }

        // Calculate fingerprint (SHA3-512 of Dilithium pubkey)
        uint8_t fingerprint[64];
        if (qgp_sha3_512(member_id->dilithium_pubkey, 2592, fingerprint) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to calculate fingerprint for %s\n", member_identity);
            dna_identity_free(member_id);
            continue;
        }

        // Allocate Kyber pubkey buffer
        kyber_pubkeys[valid_members] = (uint8_t *)malloc(1568);  // Kyber1024 pubkey size
        if (!kyber_pubkeys[valid_members]) {
            QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed\n");
            dna_identity_free(member_id);
            continue;
        }

        // Copy Kyber pubkey from identity
        memcpy(kyber_pubkeys[valid_members], member_id->kyber_pubkey, 1568);

        // Populate member entry
        memcpy(member_entries[valid_members].fingerprint, fingerprint, 64);
        member_entries[valid_members].kyber_pubkey = kyber_pubkeys[valid_members];
        valid_members++;

        dna_identity_free(member_id);
    }

    if (valid_members == 0) {
        QGP_LOG_ERROR(LOG_TAG, "No valid members found, aborting rotation\n");
        free(member_entries);
        free(kyber_pubkeys);
        dht_groups_free_metadata(meta);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Found Kyber pubkeys for %zu/%u members\n", valid_members, meta->member_count);

    // Step 5: Load owner's Dilithium5 private key for signing
    // TODO: This needs to be fetched from the messenger context or identity manager
    const char *gsk_data_dir = qgp_platform_app_data_dir();
    char privkey_path[512];
    snprintf(privkey_path, sizeof(privkey_path), "%s/%s-dilithium.pqkey", gsk_data_dir ?: ".", owner_identity);

    FILE *fp = fopen(privkey_path, "rb");
    if (!fp) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open owner private key: %s\n", privkey_path);
        for (size_t i = 0; i < valid_members; i++) {
            free(kyber_pubkeys[i]);
        }
        free(kyber_pubkeys);
        free(member_entries);
        dht_groups_free_metadata(meta);
        return -1;
    }

    uint8_t owner_privkey[4896];  // Dilithium5 private key size
    if (fread(owner_privkey, 1, 4896, fp) != 4896) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to read owner private key\n");
        fclose(fp);
        for (size_t i = 0; i < valid_members; i++) {
            free(kyber_pubkeys[i]);
        }
        free(kyber_pubkeys);
        free(member_entries);
        dht_groups_free_metadata(meta);
        return -1;
    }
    fclose(fp);

    // Step 6: Build Initial Key Packet
    uint8_t *packet = NULL;
    size_t packet_size = 0;
    if (gsk_packet_build(group_uuid, new_version, new_gsk, member_entries, valid_members,
                         owner_privkey, &packet, &packet_size) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to build Initial Key Packet\n");
        for (size_t i = 0; i < valid_members; i++) {
            free(kyber_pubkeys[i]);
        }
        free(kyber_pubkeys);
        free(member_entries);
        dht_groups_free_metadata(meta);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Built Initial Key Packet: %zu bytes\n", packet_size);

    // Cleanup
    for (size_t i = 0; i < valid_members; i++) {
        free(kyber_pubkeys[i]);
    }
    free(kyber_pubkeys);
    free(member_entries);
    dht_groups_free_metadata(meta);

    // Step 7: Publish to DHT via chunked storage
    if (dht_gsk_publish(dht_ctx, group_uuid, new_version, packet, packet_size) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish Initial Key Packet to DHT\n");
        free(packet);
        return -1;
    }

    free(packet);

    QGP_LOG_INFO(LOG_TAG, "✓ GSK rotation complete for group %s (v%u published to DHT)\n",
           group_uuid, new_version);

    // TODO Phase 8: Send P2P notifications to all members about new GSK version
    // For now, members will discover via background polling

    return 0;
}

/**
 * Rotate GSK when a member is added to the group
 */
int gsk_rotate_on_member_add(void *dht_ctx, const char *group_uuid, const char *owner_identity) {
    QGP_LOG_INFO(LOG_TAG, "Member added to group %s, rotating GSK...\n", group_uuid);
    return gsk_rotate_and_publish((dht_context_t *)dht_ctx, group_uuid, owner_identity);
}

/**
 * Rotate GSK when a member is removed from the group
 */
int gsk_rotate_on_member_remove(void *dht_ctx, const char *group_uuid, const char *owner_identity) {
    QGP_LOG_INFO(LOG_TAG, "Member removed from group %s, rotating GSK...\n", group_uuid);
    return gsk_rotate_and_publish((dht_context_t *)dht_ctx, group_uuid, owner_identity);
}
