/**
 * @file gek.c
 * @brief Group Encryption Key (GEK) Manager Implementation
 *
 * Manages AES-256 symmetric keys for group messaging encryption.
 * Consolidates key generation, storage, encryption, and rotation.
 *
 * Part of DNA Messenger - GEK System
 *
 * @date 2026-01-10
 */

#include "gek.h"
#include "group_database.h"
#include "../crypto/utils/qgp_random.h"
#include "../crypto/utils/qgp_sha3.h"
#include "../crypto/utils/qgp_platform.h"
#include "../crypto/utils/qgp_kyber.h"
#include "../crypto/utils/qgp_aes.h"
#include "../crypto/utils/qgp_dilithium.h"
#include "../crypto/utils/aes_keywrap.h"
#include "../crypto/utils/qgp_log.h"
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
#include "../dht/core/dht_context.h"
#include "../dht/core/dht_keyserver.h"
#include "../dht/shared/dht_groups.h"
#include "../dht/shared/dht_gek_storage.h"
#include "../dht/client/dht_geks.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>

#define LOG_TAG "MSG_GEK"

/* ============================================================================
 * STATIC VARIABLES
 * ============================================================================ */

// Database handle (set during gek_init)
static sqlite3 *msg_db = NULL;

// KEM keys for GEK encryption (set via gek_set_kem_keys)
static uint8_t *gek_kem_pubkey = NULL;   // 1568 bytes (Kyber1024)
static uint8_t *gek_kem_privkey = NULL;  // 3168 bytes (Kyber1024)

/* ============================================================================
 * ENCRYPTION / DECRYPTION
 * ============================================================================ */

int gek_encrypt(
    const uint8_t gek[32],
    const uint8_t kem_pubkey[1568],
    uint8_t encrypted_out[GEK_ENC_TOTAL_SIZE]
) {
    if (!gek || !kem_pubkey || !encrypted_out) {
        QGP_LOG_ERROR(LOG_TAG, "gek_encrypt: NULL parameter");
        return -1;
    }

    /* Buffers for KEM and AES */
    uint8_t kem_ciphertext[GEK_ENC_KEM_CT_SIZE];
    uint8_t shared_secret[32];  /* Kyber1024 shared secret is 32 bytes */
    uint8_t nonce[GEK_ENC_NONCE_SIZE];
    uint8_t tag[GEK_ENC_TAG_SIZE];
    uint8_t encrypted_gek[GEK_ENC_KEY_SIZE];
    size_t encrypted_len = 0;

    /* Step 1: Kyber1024 encapsulation */
    QGP_LOG_DEBUG(LOG_TAG, "Performing KEM encapsulation for GEK...");
    if (qgp_kem1024_encapsulate(kem_ciphertext, shared_secret, kem_pubkey) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "KEM encapsulation failed");
        return -1;
    }

    /* Step 2: AES-256-GCM encryption of GEK */
    QGP_LOG_DEBUG(LOG_TAG, "Encrypting GEK with AES-256-GCM...");
    if (qgp_aes256_encrypt(
            shared_secret,              /* 32-byte key from KEM */
            gek, GEK_ENC_KEY_SIZE,      /* plaintext: GEK */
            NULL, 0,                    /* no AAD */
            encrypted_gek, &encrypted_len,
            nonce, tag) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "AES-256-GCM encryption failed");
        qgp_secure_memzero(shared_secret, sizeof(shared_secret));
        return -1;
    }

    if (encrypted_len != GEK_ENC_KEY_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "Unexpected encrypted length: %zu (expected %d)",
                      encrypted_len, GEK_ENC_KEY_SIZE);
        qgp_secure_memzero(shared_secret, sizeof(shared_secret));
        return -1;
    }

    /* Step 3: Pack into output buffer */
    /* Format: kem_ciphertext (1568) || nonce (12) || tag (16) || encrypted_gek (32) */
    size_t offset = 0;
    memcpy(encrypted_out + offset, kem_ciphertext, GEK_ENC_KEM_CT_SIZE);
    offset += GEK_ENC_KEM_CT_SIZE;
    memcpy(encrypted_out + offset, nonce, GEK_ENC_NONCE_SIZE);
    offset += GEK_ENC_NONCE_SIZE;
    memcpy(encrypted_out + offset, tag, GEK_ENC_TAG_SIZE);
    offset += GEK_ENC_TAG_SIZE;
    memcpy(encrypted_out + offset, encrypted_gek, GEK_ENC_KEY_SIZE);

    /* Securely wipe sensitive data */
    qgp_secure_memzero(shared_secret, sizeof(shared_secret));
    qgp_secure_memzero(encrypted_gek, sizeof(encrypted_gek));

    QGP_LOG_DEBUG(LOG_TAG, "GEK encrypted successfully (%d bytes)", GEK_ENC_TOTAL_SIZE);
    return 0;
}

int gek_decrypt(
    const uint8_t *encrypted,
    size_t encrypted_len,
    const uint8_t kem_privkey[3168],
    uint8_t gek_out[32]
) {
    if (!encrypted || !kem_privkey || !gek_out) {
        QGP_LOG_ERROR(LOG_TAG, "gek_decrypt: NULL parameter");
        return -1;
    }

    if (encrypted_len != GEK_ENC_TOTAL_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid encrypted GEK size: %zu (expected %d)",
                      encrypted_len, GEK_ENC_TOTAL_SIZE);
        return -1;
    }

    /* Buffers for KEM and AES */
    uint8_t shared_secret[32];
    size_t decrypted_len = 0;

    /* Parse encrypted buffer */
    size_t offset = 0;
    const uint8_t *kem_ciphertext = encrypted + offset;
    offset += GEK_ENC_KEM_CT_SIZE;
    const uint8_t *nonce = encrypted + offset;
    offset += GEK_ENC_NONCE_SIZE;
    const uint8_t *tag = encrypted + offset;
    offset += GEK_ENC_TAG_SIZE;
    const uint8_t *encrypted_gek = encrypted + offset;

    /* Step 1: Kyber1024 decapsulation */
    QGP_LOG_DEBUG(LOG_TAG, "Performing KEM decapsulation for GEK...");
    if (qgp_kem1024_decapsulate(shared_secret, kem_ciphertext, kem_privkey) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "KEM decapsulation failed");
        return -1;
    }

    /* Step 2: AES-256-GCM decryption */
    QGP_LOG_DEBUG(LOG_TAG, "Decrypting GEK with AES-256-GCM...");
    if (qgp_aes256_decrypt(
            shared_secret,
            encrypted_gek, GEK_ENC_KEY_SIZE,
            NULL, 0,  /* no AAD */
            nonce, tag,
            gek_out, &decrypted_len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "AES-256-GCM decryption failed (auth tag mismatch?)");
        qgp_secure_memzero(shared_secret, sizeof(shared_secret));
        qgp_secure_memzero(gek_out, 32);
        return -1;
    }

    if (decrypted_len != GEK_ENC_KEY_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "Unexpected decrypted length: %zu (expected %d)",
                      decrypted_len, GEK_ENC_KEY_SIZE);
        qgp_secure_memzero(shared_secret, sizeof(shared_secret));
        qgp_secure_memzero(gek_out, 32);
        return -1;
    }

    /* Securely wipe sensitive data */
    qgp_secure_memzero(shared_secret, sizeof(shared_secret));

    QGP_LOG_DEBUG(LOG_TAG, "GEK decrypted successfully");
    return 0;
}

/* ============================================================================
 * KEY GENERATION AND MANAGEMENT
 * ============================================================================ */

int gek_generate(const char *group_uuid, uint32_t version, uint8_t gek_out[GEK_KEY_SIZE]) {
    if (!group_uuid || !gek_out) {
        QGP_LOG_ERROR(LOG_TAG, "gek_generate: NULL parameter\n");
        return -1;
    }

    // Generate 32 random bytes for AES-256 key
    if (qgp_randombytes(gek_out, GEK_KEY_SIZE) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate random GEK\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Generated GEK for group %s v%u\n", group_uuid, version);
    return 0;
}

int gek_store(const char *group_uuid, uint32_t version, const uint8_t gek[GEK_KEY_SIZE]) {
    if (!group_uuid || !gek) {
        QGP_LOG_ERROR(LOG_TAG, "gek_store: NULL parameter\n");
        return -1;
    }

    if (!msg_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!gek_kem_pubkey) {
        QGP_LOG_ERROR(LOG_TAG, "KEM keys not set - call gek_set_kem_keys() first\n");
        return -1;
    }

    /* Encrypt GEK with Kyber1024 KEM + AES-256-GCM */
    uint8_t encrypted_gek[GEK_ENC_TOTAL_SIZE];
    if (gek_encrypt(gek, gek_kem_pubkey, encrypted_gek) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to encrypt GEK\n");
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);
    uint64_t expires_at = now + GEK_DEFAULT_EXPIRY;

    const char *sql = "INSERT OR REPLACE INTO group_geks "
                      "(group_uuid, version, encrypted_key, created_at, expires_at) "
                      "VALUES (?, ?, ?, ?, ?)";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(msg_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(msg_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, (int)version);
    sqlite3_bind_blob(stmt, 3, encrypted_gek, GEK_ENC_TOTAL_SIZE, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)now);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)expires_at);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to store GEK: %s\n", sqlite3_errmsg(msg_db));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Stored encrypted GEK for group %s v%u (expires in %d days)\n",
           group_uuid, version, GEK_DEFAULT_EXPIRY / (24 * 3600));
    return 0;
}

int gek_load(const char *group_uuid, uint32_t version, uint8_t gek_out[GEK_KEY_SIZE]) {
    if (!group_uuid || !gek_out) {
        QGP_LOG_ERROR(LOG_TAG, "gek_load: NULL parameter\n");
        return -1;
    }

    if (!msg_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!gek_kem_privkey) {
        QGP_LOG_ERROR(LOG_TAG, "KEM keys not set - call gek_set_kem_keys() first\n");
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);

    const char *sql = "SELECT encrypted_key FROM group_geks "
                      "WHERE group_uuid = ? AND version = ? AND expires_at > ?";

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

        /* Decrypt encrypted GEK */
        if (gek_decrypt((const uint8_t *)blob, (size_t)blob_size, gek_kem_privkey, gek_out) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to decrypt GEK for group %s v%u\n", group_uuid, version);
            sqlite3_finalize(stmt);
            return -1;
        }

        sqlite3_finalize(stmt);

        QGP_LOG_INFO(LOG_TAG, "Loaded and decrypted GEK for group %s v%u\n", group_uuid, version);
        return 0;
    }

    sqlite3_finalize(stmt);

    if (rc == SQLITE_DONE) {
        QGP_LOG_INFO(LOG_TAG, "No active GEK found for group %s v%u\n", group_uuid, version);
    } else {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load GEK: %s\n", sqlite3_errmsg(msg_db));
    }

    return -1;
}

int gek_load_active(const char *group_uuid, uint8_t gek_out[GEK_KEY_SIZE], uint32_t *version_out) {
    if (!group_uuid || !gek_out) {
        QGP_LOG_ERROR(LOG_TAG, "gek_load_active: NULL parameter\n");
        return -1;
    }

    if (!msg_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!gek_kem_privkey) {
        QGP_LOG_ERROR(LOG_TAG, "KEM keys not set - call gek_set_kem_keys() first\n");
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);

    const char *sql = "SELECT encrypted_key, version FROM group_geks "
                      "WHERE group_uuid = ? AND expires_at > ? "
                      "ORDER BY version DESC LIMIT 1";

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

        /* Decrypt encrypted GEK */
        if (gek_decrypt((const uint8_t *)blob, (size_t)blob_size, gek_kem_privkey, gek_out) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to decrypt active GEK for group %s\n", group_uuid);
            sqlite3_finalize(stmt);
            return -1;
        }

        if (version_out) {
            *version_out = version;
        }

        sqlite3_finalize(stmt);

        QGP_LOG_INFO(LOG_TAG, "Loaded and decrypted active GEK for group %s v%u\n", group_uuid, version);
        return 0;
    }

    sqlite3_finalize(stmt);

    if (rc == SQLITE_DONE) {
        QGP_LOG_INFO(LOG_TAG, "No active GEK found for group %s\n", group_uuid);
    } else {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load active GEK: %s\n", sqlite3_errmsg(msg_db));
    }

    return -1;
}

int gek_rotate(const char *group_uuid, uint32_t *new_version_out, uint8_t new_gek_out[GEK_KEY_SIZE]) {
    if (!group_uuid || !new_version_out || !new_gek_out) {
        QGP_LOG_ERROR(LOG_TAG, "gek_rotate: NULL parameter\n");
        return -1;
    }

    // Get current version
    uint32_t current_version = 0;
    int rc = gek_get_current_version(group_uuid, &current_version);
    if (rc != 0) {
        // No existing GEK, start at version 0
        current_version = 0;
        QGP_LOG_INFO(LOG_TAG, "No existing GEK found, starting at version 0\n");
    }

    // Use Unix timestamp for version (fits in uint32_t until year 2106)
    // This allows distributed clients to generate versions without coordination
    uint32_t new_version = (uint32_t)time(NULL);
    // Ensure always increasing (handles edge case of multiple rotations in same second
    // or if clock went backwards)
    if (new_version <= current_version) {
        new_version = current_version + 1;
    }

    // Generate new GEK
    rc = gek_generate(group_uuid, new_version, new_gek_out);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate new GEK\n");
        return -1;
    }

    *new_version_out = new_version;

    QGP_LOG_INFO(LOG_TAG, "Rotated GEK for group %s: v%u -> v%u\n",
           group_uuid, current_version, new_version);
    return 0;
}

int gek_get_current_version(const char *group_uuid, uint32_t *version_out) {
    if (!group_uuid || !version_out) {
        QGP_LOG_ERROR(LOG_TAG, "gek_get_current_version: NULL parameter\n");
        return -1;
    }

    if (!msg_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    const char *sql = "SELECT MAX(version) FROM group_geks WHERE group_uuid = ?";

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
            // No GEK exists for this group
            *version_out = 0;
            sqlite3_finalize(stmt);
            return -1;
        }
    }

    sqlite3_finalize(stmt);
    QGP_LOG_ERROR(LOG_TAG, "Failed to get current version: %s\n", sqlite3_errmsg(msg_db));
    return -1;
}

int gek_cleanup_expired(void) {
    if (!msg_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);

    const char *sql = "DELETE FROM group_geks WHERE expires_at <= ?";

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
        QGP_LOG_ERROR(LOG_TAG, "Failed to cleanup expired GEKs: %s\n", sqlite3_errmsg(msg_db));
        return -1;
    }

    int deleted = sqlite3_changes(msg_db);
    if (deleted > 0) {
        QGP_LOG_INFO(LOG_TAG, "Cleaned up %d expired GEK entries\n", deleted);
    }

    return deleted;
}

/* ============================================================================
 * INITIALIZATION
 * ============================================================================ */

int gek_init(void *unused_ctx) {
    (void)unused_ctx;  // Legacy parameter, no longer used

    // Get database handle from group_database singleton
    group_database_context_t *grp_db_ctx = group_database_get_instance();
    if (!grp_db_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "group_database not initialized - call group_database_init() first\n");
        return -1;
    }

    msg_db = (sqlite3 *)group_database_get_db(grp_db_ctx);
    if (!msg_db) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get database handle from group_database\n");
        return -1;
    }

    // Table created by group_database.c
    // Just verify it exists
    const char *verify_sql = "SELECT 1 FROM group_geks LIMIT 1";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(msg_db, verify_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "group_geks table not found in groups.db\n");
        return -1;
    }
    sqlite3_finalize(stmt);

    QGP_LOG_INFO(LOG_TAG, "Initialized GEK subsystem (using groups.db)\n");

    // Cleanup expired entries on startup
    gek_cleanup_expired();

    return 0;
}

int gek_set_kem_keys(const uint8_t *kem_pubkey, const uint8_t *kem_privkey) {
    if (!kem_pubkey || !kem_privkey) {
        QGP_LOG_ERROR(LOG_TAG, "gek_set_kem_keys: NULL parameter\n");
        return -1;
    }

    /* Clear existing keys if any */
    gek_clear_kem_keys();

    /* Allocate and copy public key (1568 bytes) */
    gek_kem_pubkey = malloc(1568);
    if (!gek_kem_pubkey) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate KEM pubkey\n");
        return -1;
    }
    memcpy(gek_kem_pubkey, kem_pubkey, 1568);

    /* Allocate and copy private key (3168 bytes) */
    gek_kem_privkey = malloc(3168);
    if (!gek_kem_privkey) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate KEM privkey\n");
        qgp_secure_memzero(gek_kem_pubkey, 1568);
        free(gek_kem_pubkey);
        gek_kem_pubkey = NULL;
        return -1;
    }
    memcpy(gek_kem_privkey, kem_privkey, 3168);

    QGP_LOG_INFO(LOG_TAG, "KEM keys set for GEK encryption\n");
    return 0;
}

void gek_clear_kem_keys(void) {
    if (gek_kem_pubkey) {
        qgp_secure_memzero(gek_kem_pubkey, 1568);
        free(gek_kem_pubkey);
        gek_kem_pubkey = NULL;
    }
    if (gek_kem_privkey) {
        qgp_secure_memzero(gek_kem_privkey, 3168);
        free(gek_kem_privkey);
        gek_kem_privkey = NULL;
    }
    QGP_LOG_DEBUG(LOG_TAG, "KEM keys cleared\n");
}

/* ============================================================================
 * MEMBER CHANGE HANDLERS
 * ============================================================================ */

/**
 * Helper: Rotate GEK and publish to DHT
 *
 * Common logic for both member add/remove operations.
 */
static int gek_rotate_and_publish(dht_context_t *dht_ctx, const char *group_uuid, const char *owner_identity) {
    if (!dht_ctx || !group_uuid || !owner_identity) {
        QGP_LOG_ERROR(LOG_TAG, "gek_rotate_and_publish: NULL parameter\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Rotating GEK for group %s (owner=%s)\n", group_uuid, owner_identity);

    // Step 1: Rotate GEK (increment version, generate new key)
    uint32_t new_version = 0;
    uint8_t new_gek[GEK_KEY_SIZE];
    if (gek_rotate(group_uuid, &new_version, new_gek) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to rotate GEK\n");
        return -1;
    }

    // Step 2: Store new GEK locally
    if (gek_store(group_uuid, new_version, new_gek) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to store new GEK\n");
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
    gek_member_entry_t *member_entries = (gek_member_entry_t *)calloc(meta->member_count, sizeof(gek_member_entry_t));
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
    // v0.3.0: Flat structure - keys/identity.dsa
    const char *gek_data_dir = qgp_platform_app_data_dir();
    char privkey_path[512];
    snprintf(privkey_path, sizeof(privkey_path), "%s/keys/identity.dsa", gek_data_dir ? gek_data_dir : ".");

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
    if (ikp_build(group_uuid, new_version, new_gek, (const gek_member_entry_t *)member_entries, valid_members,
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
    if (dht_gek_publish(dht_ctx, group_uuid, new_version, packet, packet_size) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish Initial Key Packet to DHT\n");
        free(packet);
        return -1;
    }

    free(packet);

    // Step 8: Update group metadata with new GEK version
    // This allows invitees to know which IKP version to fetch
    if (dht_groups_update_gek_version(dht_ctx, group_uuid, new_version) != 0) {
        QGP_LOG_WARN(LOG_TAG, "Failed to update GEK version in metadata (IKP still published)\n");
        // Non-fatal: IKP is published, metadata update is best-effort
    }

    QGP_LOG_INFO(LOG_TAG, "GEK rotation complete for group %s (v%u published to DHT)\n",
           group_uuid, new_version);

    return 0;
}

int gek_rotate_on_member_add(void *dht_ctx, const char *group_uuid, const char *owner_identity) {
    QGP_LOG_INFO(LOG_TAG, "Member added to group %s, rotating GEK...\n", group_uuid);
    return gek_rotate_and_publish((dht_context_t *)dht_ctx, group_uuid, owner_identity);
}

int gek_rotate_on_member_remove(void *dht_ctx, const char *group_uuid, const char *owner_identity) {
    QGP_LOG_INFO(LOG_TAG, "Member removed from group %s, rotating GEK...\n", group_uuid);
    return gek_rotate_and_publish((dht_context_t *)dht_ctx, group_uuid, owner_identity);
}

/* ============================================================================
 * IKP (Initial Key Packet) FUNCTIONS
 * ============================================================================ */

size_t ikp_calculate_size(size_t member_count) {
    return IKP_HEADER_SIZE + (IKP_MEMBER_ENTRY_SIZE * member_count) + IKP_SIGNATURE_SIZE;
}

int ikp_build(const char *group_uuid,
              uint32_t version,
              const uint8_t gek[GEK_KEY_SIZE],
              const gek_member_entry_t *members,
              size_t member_count,
              const uint8_t *owner_dilithium_privkey,
              uint8_t **packet_out,
              size_t *packet_size_out) {
    if (!group_uuid || !gek || !members || member_count == 0 ||
        !owner_dilithium_privkey || !packet_out || !packet_size_out) {
        QGP_LOG_ERROR(LOG_TAG, "ikp_build: NULL parameter\n");
        return -1;
    }

    // Validate member count to prevent memory exhaustion
    if (member_count > IKP_MAX_MEMBERS) {
        QGP_LOG_ERROR(LOG_TAG, "ikp_build: member_count %zu exceeds maximum %d\n",
                      member_count, IKP_MAX_MEMBERS);
        return -1;
    }

    // Calculate packet size
    size_t packet_size = ikp_calculate_size(member_count);
    uint8_t *packet = (uint8_t *)malloc(packet_size);
    if (!packet) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate packet buffer\n");
        return -1;
    }

    size_t offset = 0;

    // === HEADER ===
    // Magic bytes: "GEK " (4 bytes)
    uint32_t magic = htonl(IKP_MAGIC);
    memcpy(packet + offset, &magic, 4);
    offset += 4;

    // Group UUID (36 bytes, no null terminator in packet)
    memcpy(packet + offset, group_uuid, 36);
    offset += 36;

    // GEK version (4 bytes, network byte order)
    uint32_t version_net = htonl(version);
    memcpy(packet + offset, &version_net, 4);
    offset += 4;

    // Member count (1 byte)
    packet[offset] = (uint8_t)member_count;
    offset += 1;

    QGP_LOG_INFO(LOG_TAG, "Building IKP for group %.8s... v%u with %zu members\n",
           group_uuid, version, member_count);

    // === PER-MEMBER ENTRIES ===
    for (size_t i = 0; i < member_count; i++) {
        const gek_member_entry_t *member = &members[i];

        // Fingerprint (64 bytes binary)
        memcpy(packet + offset, member->fingerprint, 64);
        offset += 64;

        // Kyber1024 encapsulation: (GEK -> KEK, ciphertext)
        uint8_t kyber_ct[QGP_KEM1024_CIPHERTEXTBYTES];  // 1568 bytes
        uint8_t kek[QGP_KEM1024_SHAREDSECRET_BYTES];     // 32 bytes

        int ret = qgp_kem1024_encapsulate(kyber_ct, kek, member->kyber_pubkey);

        if (ret != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Kyber1024 encapsulation failed for member %zu\n", i);
            free(packet);
            return -1;
        }

        memcpy(packet + offset, kyber_ct, 1568);
        offset += 1568;

        // AES key wrap: Wrap GEK with KEK
        uint8_t wrapped_gek[40];  // AES-wrap output: 32-byte key -> 40 bytes
        if (aes256_wrap_key(gek, GEK_KEY_SIZE, kek, wrapped_gek) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "AES key wrap failed for member %zu\n", i);
            free(packet);
            return -1;
        }

        memcpy(packet + offset, wrapped_gek, 40);
        offset += 40;

        QGP_LOG_DEBUG(LOG_TAG, "Member %zu: Kyber+Wrap OK\n", i);
    }

    // === SIGNATURE ===
    // Sign the packet up to this point (header + entries)
    size_t data_to_sign_len = offset;
    uint8_t signature[QGP_DSA87_SIGNATURE_BYTES];  // Pre-allocated buffer (4627 bytes)
    size_t sig_len = 0;

    int ret = qgp_dsa87_sign(signature, &sig_len, packet, data_to_sign_len,
                              owner_dilithium_privkey);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Dilithium5 signing failed\n");
        free(packet);
        return -1;
    }

    // Signature type (1 byte: 23 = Dilithium5 / ML-DSA-87)
    packet[offset] = 23;
    offset += 1;

    // Signature size (2 bytes, network byte order)
    uint16_t sig_size_net = htons((uint16_t)sig_len);
    memcpy(packet + offset, &sig_size_net, 2);
    offset += 2;

    // Signature bytes
    memcpy(packet + offset, signature, sig_len);
    offset += sig_len;

    QGP_LOG_INFO(LOG_TAG, "IKP built: %zu bytes (signed)\n", offset);

    *packet_out = packet;
    *packet_size_out = offset;
    return 0;
}

int ikp_extract(const uint8_t *packet,
                size_t packet_size,
                const uint8_t *my_fingerprint_bin,
                const uint8_t *my_kyber_privkey,
                uint8_t gek_out[GEK_KEY_SIZE],
                uint32_t *version_out) {
    if (!packet || packet_size < IKP_HEADER_SIZE ||
        !my_fingerprint_bin || !my_kyber_privkey || !gek_out) {
        QGP_LOG_ERROR(LOG_TAG, "ikp_extract: Invalid parameter\n");
        return -1;
    }

    size_t offset = 0;

    // === PARSE HEADER ===
    // Magic bytes (4 bytes)
    uint32_t magic;
    memcpy(&magic, packet + offset, 4);
    magic = ntohl(magic);
    offset += 4;

    if (magic != IKP_MAGIC) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid IKP magic: 0x%08X (expected 0x%08X)\n", magic, IKP_MAGIC);
        return -1;
    }

    // Group UUID (36 bytes)
    char group_uuid[37];
    memcpy(group_uuid, packet + offset, 36);
    group_uuid[36] = '\0';
    offset += 36;

    // GEK version (4 bytes)
    uint32_t version;
    memcpy(&version, packet + offset, 4);
    version = ntohl(version);
    offset += 4;

    if (version_out) {
        *version_out = version;
    }

    // Member count (1 byte)
    uint8_t member_count = packet[offset];
    offset += 1;

    // Validate member count to prevent malicious packets
    if (member_count == 0 || member_count > IKP_MAX_MEMBERS) {
        QGP_LOG_ERROR(LOG_TAG, "ikp_extract: invalid member_count %u (max=%d)\n",
                      member_count, IKP_MAX_MEMBERS);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Extracting from IKP: group=%.8s... v%u members=%u\n",
           group_uuid, version, member_count);

    // === SEARCH FOR MY ENTRY ===
    for (size_t i = 0; i < member_count; i++) {
        // Read fingerprint (64 bytes)
        if (offset + 64 > packet_size) {
            QGP_LOG_ERROR(LOG_TAG, "Packet truncated at member %zu\n", i);
            return -1;
        }

        const uint8_t *entry_fingerprint = packet + offset;

        // Check if this is my entry
        if (memcmp(entry_fingerprint, my_fingerprint_bin, 64) == 0) {
            QGP_LOG_INFO(LOG_TAG, "Found my entry at position %zu\n", i);

            offset += 64;

            // Kyber1024 ciphertext (1568 bytes)
            if (offset + 1568 > packet_size) {
                QGP_LOG_ERROR(LOG_TAG, "Packet truncated at kyber_ct\n");
                return -1;
            }
            const uint8_t *kyber_ct = packet + offset;
            offset += 1568;

            // Wrapped GEK (40 bytes)
            if (offset + 40 > packet_size) {
                QGP_LOG_ERROR(LOG_TAG, "Packet truncated at wrapped_gek\n");
                return -1;
            }
            const uint8_t *wrapped_gek = packet + offset;

            // Kyber1024 decapsulation: ciphertext -> KEK
            uint8_t kek[QGP_KEM1024_SHAREDSECRET_BYTES];  // 32 bytes
            int ret = qgp_kem1024_decapsulate(kek, kyber_ct, my_kyber_privkey);

            if (ret != 0) {
                QGP_LOG_ERROR(LOG_TAG, "Kyber1024 decapsulation failed\n");
                return -1;
            }

            // AES key unwrap: wrapped_gek + KEK -> GEK
            if (aes256_unwrap_key(wrapped_gek, 40, kek, gek_out) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "AES key unwrap failed\n");
                return -1;
            }

            QGP_LOG_INFO(LOG_TAG, "Successfully extracted GEK\n");
            return 0;
        }

        // Not my entry, skip to next
        offset += 64 + 1568 + 40;  // fingerprint + kyber_ct + wrapped_gek
    }

    QGP_LOG_ERROR(LOG_TAG, "My fingerprint not found in packet\n");
    return -1;
}

int ikp_verify(const uint8_t *packet,
               size_t packet_size,
               const uint8_t *owner_dilithium_pubkey) {
    if (!packet || packet_size < IKP_HEADER_SIZE ||
        !owner_dilithium_pubkey) {
        QGP_LOG_ERROR(LOG_TAG, "ikp_verify: Invalid parameter\n");
        return -1;
    }

    // Verify magic
    uint32_t magic;
    memcpy(&magic, packet, 4);
    magic = ntohl(magic);
    if (magic != IKP_MAGIC) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid IKP magic\n");
        return -1;
    }

    // Parse header to get member count
    uint8_t member_count = packet[IKP_HEADER_SIZE - 1];

    // Validate member count
    if (member_count == 0 || member_count > IKP_MAX_MEMBERS) {
        QGP_LOG_ERROR(LOG_TAG, "ikp_verify: invalid member_count %u (max=%d)\n",
                      member_count, IKP_MAX_MEMBERS);
        return -1;
    }

    // Calculate where signature starts
    size_t signature_offset = IKP_HEADER_SIZE + (IKP_MEMBER_ENTRY_SIZE * member_count);

    if (signature_offset + 3 > packet_size) {
        QGP_LOG_ERROR(LOG_TAG, "Packet too small for signature\n");
        return -1;
    }

    // Parse signature block
    uint8_t sig_type = packet[signature_offset];
    if (sig_type != 23) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid signature type: %u (expected 23)\n", sig_type);
        return -1;
    }

    uint16_t sig_size;
    memcpy(&sig_size, packet + signature_offset + 1, 2);
    sig_size = ntohs(sig_size);

    const uint8_t *signature = packet + signature_offset + 3;

    if (signature_offset + 3 + sig_size > packet_size) {
        QGP_LOG_ERROR(LOG_TAG, "Signature size mismatch\n");
        return -1;
    }

    // Verify signature (signed data is everything before signature)
    int ret = qgp_dsa87_verify(signature, sig_size, packet, signature_offset,
                                owner_dilithium_pubkey);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Signature verification FAILED\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Signature verification OK\n");
    return 0;
}

int ikp_get_version(const uint8_t *packet, size_t packet_size, uint32_t *version_out) {
    if (!packet || packet_size < IKP_HEADER_SIZE || !version_out) {
        return -1;
    }

    // Verify magic
    uint32_t magic;
    memcpy(&magic, packet, 4);
    magic = ntohl(magic);
    if (magic != IKP_MAGIC) {
        return -1;
    }

    // Version is at offset 40 (magic:4 + uuid:36)
    uint32_t version;
    memcpy(&version, packet + 40, 4);
    *version_out = ntohl(version);
    return 0;
}

int ikp_get_member_count(const uint8_t *packet, size_t packet_size, uint8_t *count_out) {
    if (!packet || packet_size < IKP_HEADER_SIZE || !count_out) {
        return -1;
    }

    // Verify magic
    uint32_t magic;
    memcpy(&magic, packet, 4);
    magic = ntohl(magic);
    if (magic != IKP_MAGIC) {
        return -1;
    }

    // Member count is at offset 44 (magic:4 + uuid:36 + version:4)
    *count_out = packet[44];
    return 0;
}

/* ============================================================================
 * BACKUP / RESTORE (Multi-Device Sync)
 * ============================================================================ */

int gek_export_all(gek_export_entry_t **entries_out, size_t *count_out) {
    if (!entries_out || !count_out) {
        QGP_LOG_ERROR(LOG_TAG, "gek_export_all: NULL parameter");
        return -1;
    }

    *entries_out = NULL;
    *count_out = 0;

    if (!msg_db) {
        // Not an error - GEK module not used yet, return empty
        QGP_LOG_DEBUG(LOG_TAG, "gek_export_all: No database (not initialized)");
        return 0;
    }

    // Count GEK entries
    const char *count_sql = "SELECT COUNT(*) FROM group_geks";
    sqlite3_stmt *count_stmt;
    if (sqlite3_prepare_v2(msg_db, count_sql, -1, &count_stmt, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare count statement: %s", sqlite3_errmsg(msg_db));
        return -1;
    }

    size_t total_count = 0;
    if (sqlite3_step(count_stmt) == SQLITE_ROW) {
        total_count = (size_t)sqlite3_column_int(count_stmt, 0);
    }
    sqlite3_finalize(count_stmt);

    if (total_count == 0) {
        QGP_LOG_INFO(LOG_TAG, "No GEK entries to export");
        return 0;
    }

    // Allocate output array
    gek_export_entry_t *entries = calloc(total_count, sizeof(gek_export_entry_t));
    if (!entries) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate export entries");
        return -1;
    }

    // Query all GEK entries (encrypted_key is already encrypted in DB)
    const char *select_sql =
        "SELECT group_uuid, version, encrypted_key, created_at, expires_at FROM group_geks";
    sqlite3_stmt *select_stmt;

    if (sqlite3_prepare_v2(msg_db, select_sql, -1, &select_stmt, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare select statement: %s", sqlite3_errmsg(msg_db));
        free(entries);
        return -1;
    }

    size_t idx = 0;
    while (sqlite3_step(select_stmt) == SQLITE_ROW && idx < total_count) {
        const char *uuid = (const char *)sqlite3_column_text(select_stmt, 0);
        uint32_t version = (uint32_t)sqlite3_column_int(select_stmt, 1);
        const void *enc_gek = sqlite3_column_blob(select_stmt, 2);
        int enc_gek_len = sqlite3_column_bytes(select_stmt, 2);
        uint64_t created_at = (uint64_t)sqlite3_column_int64(select_stmt, 3);
        uint64_t expires_at = (uint64_t)sqlite3_column_int64(select_stmt, 4);

        if (uuid && enc_gek && enc_gek_len == GEK_ENC_TOTAL_SIZE) {
            strncpy(entries[idx].group_uuid, uuid, 36);
            entries[idx].group_uuid[36] = '\0';
            entries[idx].gek_version = version;
            memcpy(entries[idx].encrypted_gek, enc_gek, GEK_ENC_TOTAL_SIZE);
            entries[idx].created_at = created_at;
            entries[idx].expires_at = expires_at;
            idx++;
        }
    }

    sqlite3_finalize(select_stmt);

    *entries_out = entries;
    *count_out = idx;

    QGP_LOG_INFO(LOG_TAG, "Exported %zu GEK entries for backup", idx);
    return 0;
}

int gek_import_all(const gek_export_entry_t *entries, size_t count, int *imported_out) {
    if (!entries && count > 0) {
        QGP_LOG_ERROR(LOG_TAG, "gek_import_all: NULL entries with count > 0");
        return -1;
    }

    if (imported_out) {
        *imported_out = 0;
    }

    if (count == 0) {
        QGP_LOG_INFO(LOG_TAG, "No GEK entries to import");
        return 0;
    }

    if (!msg_db) {
        QGP_LOG_ERROR(LOG_TAG, "gek_import_all: Database not initialized");
        return -1;
    }

    // Prepare insert statement (INSERT OR IGNORE to skip duplicates)
    const char *insert_sql =
        "INSERT OR IGNORE INTO group_geks "
        "(group_uuid, version, encrypted_key, created_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?)";
    sqlite3_stmt *insert_stmt;

    if (sqlite3_prepare_v2(msg_db, insert_sql, -1, &insert_stmt, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare insert statement: %s", sqlite3_errmsg(msg_db));
        return -1;
    }

    int imported = 0;
    for (size_t i = 0; i < count; i++) {
        sqlite3_reset(insert_stmt);
        sqlite3_bind_text(insert_stmt, 1, entries[i].group_uuid, -1, SQLITE_STATIC);
        sqlite3_bind_int(insert_stmt, 2, (int)entries[i].gek_version);
        sqlite3_bind_blob(insert_stmt, 3, entries[i].encrypted_gek, GEK_ENC_TOTAL_SIZE, SQLITE_STATIC);
        sqlite3_bind_int64(insert_stmt, 4, (sqlite3_int64)entries[i].created_at);
        sqlite3_bind_int64(insert_stmt, 5, (sqlite3_int64)entries[i].expires_at);

        if (sqlite3_step(insert_stmt) == SQLITE_DONE) {
            if (sqlite3_changes(msg_db) > 0) {
                imported++;
            }
        } else {
            QGP_LOG_WARN(LOG_TAG, "Failed to import GEK entry %zu: %s", i, sqlite3_errmsg(msg_db));
        }
    }

    sqlite3_finalize(insert_stmt);

    if (imported_out) {
        *imported_out = imported;
    }

    QGP_LOG_INFO(LOG_TAG, "Imported %d/%zu GEK entries from backup", imported, count);
    return 0;
}

void gek_free_export_entries(gek_export_entry_t *entries, size_t count) {
    (void)count;  // No per-entry cleanup needed
    if (entries) {
        free(entries);
    }
}

/* ============================================================================
 * DHT SYNC (Multi-Device Sync via DHT)
 * ============================================================================ */

/**
 * Helper: Export all non-expired GEKs as plain entries for DHT sync
 * Note: This decrypts the locally encrypted GEKs and exports them plain
 */
static int gek_export_plain_entries(dht_gek_entry_t **entries_out, size_t *count_out) {
    if (!entries_out || !count_out) {
        return -1;
    }

    *entries_out = NULL;
    *count_out = 0;

    if (!msg_db) {
        QGP_LOG_DEBUG(LOG_TAG, "gek_export_plain_entries: No database\n");
        return 0;
    }

    if (!gek_kem_privkey) {
        QGP_LOG_ERROR(LOG_TAG, "KEM keys not set - cannot decrypt GEKs for export\n");
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);

    // Count non-expired entries
    const char *count_sql = "SELECT COUNT(*) FROM group_geks WHERE expires_at > ?";
    sqlite3_stmt *count_stmt;
    if (sqlite3_prepare_v2(msg_db, count_sql, -1, &count_stmt, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare count statement\n");
        return -1;
    }
    sqlite3_bind_int64(count_stmt, 1, (sqlite3_int64)now);

    size_t total_count = 0;
    if (sqlite3_step(count_stmt) == SQLITE_ROW) {
        total_count = (size_t)sqlite3_column_int(count_stmt, 0);
    }
    sqlite3_finalize(count_stmt);

    if (total_count == 0) {
        QGP_LOG_INFO(LOG_TAG, "No non-expired GEKs to export\n");
        return 0;
    }

    // Allocate output array
    dht_gek_entry_t *entries = calloc(total_count, sizeof(dht_gek_entry_t));
    if (!entries) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate entries\n");
        return -1;
    }

    // Query all non-expired entries
    const char *select_sql =
        "SELECT group_uuid, version, encrypted_key, created_at, expires_at "
        "FROM group_geks WHERE expires_at > ?";
    sqlite3_stmt *select_stmt;

    if (sqlite3_prepare_v2(msg_db, select_sql, -1, &select_stmt, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare select statement\n");
        free(entries);
        return -1;
    }
    sqlite3_bind_int64(select_stmt, 1, (sqlite3_int64)now);

    size_t idx = 0;
    while (sqlite3_step(select_stmt) == SQLITE_ROW && idx < total_count) {
        const char *uuid = (const char *)sqlite3_column_text(select_stmt, 0);
        uint32_t version = (uint32_t)sqlite3_column_int(select_stmt, 1);
        const void *enc_gek = sqlite3_column_blob(select_stmt, 2);
        int enc_gek_len = sqlite3_column_bytes(select_stmt, 2);
        uint64_t created_at = (uint64_t)sqlite3_column_int64(select_stmt, 3);
        uint64_t expires_at = (uint64_t)sqlite3_column_int64(select_stmt, 4);

        if (!uuid || !enc_gek || enc_gek_len != GEK_ENC_TOTAL_SIZE) {
            continue;
        }

        // Decrypt the GEK
        uint8_t plain_gek[GEK_KEY_SIZE];
        if (gek_decrypt((const uint8_t *)enc_gek, (size_t)enc_gek_len,
                        gek_kem_privkey, plain_gek) != 0) {
            QGP_LOG_WARN(LOG_TAG, "Failed to decrypt GEK for %s v%u\n", uuid, version);
            continue;
        }

        // Populate entry
        strncpy(entries[idx].group_uuid, uuid, 36);
        entries[idx].group_uuid[36] = '\0';
        entries[idx].gek_version = version;
        memcpy(entries[idx].gek, plain_gek, GEK_KEY_SIZE);
        entries[idx].created_at = created_at;
        entries[idx].expires_at = expires_at;

        // Wipe plain GEK
        qgp_secure_memzero(plain_gek, sizeof(plain_gek));

        idx++;
    }

    sqlite3_finalize(select_stmt);

    *entries_out = entries;
    *count_out = idx;

    QGP_LOG_INFO(LOG_TAG, "Exported %zu GEK entries for DHT sync\n", idx);
    return 0;
}

/**
 * Helper: Import GEK entries from DHT sync to local database
 * Re-encrypts GEKs with local Kyber key before storing
 */
static int gek_import_plain_entries(const dht_gek_entry_t *entries, size_t count, int *imported_out) {
    if (!entries && count > 0) {
        return -1;
    }

    if (imported_out) {
        *imported_out = 0;
    }

    if (count == 0) {
        return 0;
    }

    if (!msg_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!gek_kem_pubkey) {
        QGP_LOG_ERROR(LOG_TAG, "KEM keys not set - cannot encrypt GEKs for import\n");
        return -1;
    }

    int imported = 0;

    for (size_t i = 0; i < count; i++) {
        const dht_gek_entry_t *entry = &entries[i];

        // Check if this entry already exists locally
        const char *check_sql = "SELECT 1 FROM group_geks WHERE group_uuid = ? AND version = ?";
        sqlite3_stmt *check_stmt;
        if (sqlite3_prepare_v2(msg_db, check_sql, -1, &check_stmt, NULL) != SQLITE_OK) {
            continue;
        }
        sqlite3_bind_text(check_stmt, 1, entry->group_uuid, -1, SQLITE_STATIC);
        sqlite3_bind_int(check_stmt, 2, (int)entry->gek_version);

        int exists = (sqlite3_step(check_stmt) == SQLITE_ROW);
        sqlite3_finalize(check_stmt);

        if (exists) {
            QGP_LOG_DEBUG(LOG_TAG, "GEK %s v%u already exists locally\n",
                          entry->group_uuid, entry->gek_version);
            continue;
        }

        // Encrypt the GEK with local Kyber key
        uint8_t encrypted_gek[GEK_ENC_TOTAL_SIZE];
        if (gek_encrypt(entry->gek, gek_kem_pubkey, encrypted_gek) != 0) {
            QGP_LOG_WARN(LOG_TAG, "Failed to encrypt GEK for %s v%u\n",
                         entry->group_uuid, entry->gek_version);
            continue;
        }

        // Insert into database
        const char *insert_sql =
            "INSERT INTO group_geks (group_uuid, version, encrypted_key, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?)";
        sqlite3_stmt *insert_stmt;

        if (sqlite3_prepare_v2(msg_db, insert_sql, -1, &insert_stmt, NULL) != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to prepare insert: %s\n", sqlite3_errmsg(msg_db));
            continue;
        }

        sqlite3_bind_text(insert_stmt, 1, entry->group_uuid, -1, SQLITE_STATIC);
        sqlite3_bind_int(insert_stmt, 2, (int)entry->gek_version);
        sqlite3_bind_blob(insert_stmt, 3, encrypted_gek, GEK_ENC_TOTAL_SIZE, SQLITE_STATIC);
        sqlite3_bind_int64(insert_stmt, 4, (sqlite3_int64)entry->created_at);
        sqlite3_bind_int64(insert_stmt, 5, (sqlite3_int64)entry->expires_at);

        if (sqlite3_step(insert_stmt) == SQLITE_DONE) {
            imported++;
            QGP_LOG_INFO(LOG_TAG, "Imported GEK %s v%u from DHT\n",
                         entry->group_uuid, entry->gek_version);
        }

        sqlite3_finalize(insert_stmt);
    }

    if (imported_out) {
        *imported_out = imported;
    }

    QGP_LOG_INFO(LOG_TAG, "Imported %d/%zu GEK entries from DHT sync\n", imported, count);
    return 0;
}

int gek_sync_to_dht(
    void *dht_ctx,
    const char *identity,
    const uint8_t *kyber_pubkey,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey,
    const uint8_t *dilithium_privkey)
{
    if (!dht_ctx || !identity || !kyber_pubkey || !kyber_privkey ||
        !dilithium_pubkey || !dilithium_privkey) {
        QGP_LOG_ERROR(LOG_TAG, "gek_sync_to_dht: NULL parameter\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Syncing GEKs to DHT for %.16s...\n", identity);

    // Export all local GEKs (decrypted)
    dht_gek_entry_t *entries = NULL;
    size_t count = 0;

    if (gek_export_plain_entries(&entries, &count) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to export GEKs for sync\n");
        return -1;
    }

    if (count == 0) {
        QGP_LOG_INFO(LOG_TAG, "No GEKs to sync to DHT\n");
        return 0;
    }

    // Publish to DHT
    int result = dht_geks_publish(
        (dht_context_t *)dht_ctx,
        identity,
        entries,
        count,
        kyber_pubkey,
        kyber_privkey,
        dilithium_pubkey,
        dilithium_privkey,
        0  // Use default TTL
    );

    // Secure wipe and free entries
    for (size_t i = 0; i < count; i++) {
        qgp_secure_memzero(entries[i].gek, GEK_KEY_SIZE);
    }
    free(entries);

    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish GEKs to DHT\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Successfully synced %zu GEKs to DHT\n", count);
    return 0;
}

int gek_sync_from_dht(
    void *dht_ctx,
    const char *identity,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey,
    int *imported_out)
{
    if (!dht_ctx || !identity || !kyber_privkey || !dilithium_pubkey) {
        QGP_LOG_ERROR(LOG_TAG, "gek_sync_from_dht: NULL parameter\n");
        return -1;
    }

    if (imported_out) {
        *imported_out = 0;
    }

    QGP_LOG_INFO(LOG_TAG, "Syncing GEKs from DHT for %.16s...\n", identity);

    // Fetch from DHT
    dht_gek_entry_t *entries = NULL;
    size_t count = 0;

    int result = dht_geks_fetch(
        (dht_context_t *)dht_ctx,
        identity,
        &entries,
        &count,
        kyber_privkey,
        dilithium_pubkey
    );

    if (result == -2) {
        QGP_LOG_INFO(LOG_TAG, "No GEKs found in DHT for this identity\n");
        return -2;
    }

    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to fetch GEKs from DHT\n");
        return -1;
    }

    if (count == 0) {
        QGP_LOG_INFO(LOG_TAG, "No GEKs to import from DHT\n");
        return 0;
    }

    // Import to local database
    int imported = 0;
    result = gek_import_plain_entries(entries, count, &imported);

    // Secure wipe and free entries
    for (size_t i = 0; i < count; i++) {
        qgp_secure_memzero(entries[i].gek, GEK_KEY_SIZE);
    }
    dht_geks_free_entries(entries, count);

    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to import GEKs from DHT\n");
        return -1;
    }

    if (imported_out) {
        *imported_out = imported;
    }

    QGP_LOG_INFO(LOG_TAG, "Successfully synced %d GEKs from DHT\n", imported);
    return 0;
}

int gek_auto_sync(
    void *dht_ctx,
    const char *identity,
    const uint8_t *kyber_pubkey,
    const uint8_t *kyber_privkey,
    const uint8_t *dilithium_pubkey,
    const uint8_t *dilithium_privkey)
{
    if (!dht_ctx || !identity || !kyber_pubkey || !kyber_privkey ||
        !dilithium_pubkey || !dilithium_privkey) {
        QGP_LOG_ERROR(LOG_TAG, "gek_auto_sync: NULL parameter\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Auto-syncing GEKs for %.16s...\n", identity);

    // First, try to sync from DHT (get any new GEKs from other devices)
    int imported = 0;
    int from_result = gek_sync_from_dht(dht_ctx, identity, kyber_privkey,
                                         dilithium_pubkey, &imported);

    if (from_result == -2) {
        QGP_LOG_INFO(LOG_TAG, "No GEKs in DHT, will publish local GEKs\n");
    } else if (from_result != 0) {
        QGP_LOG_WARN(LOG_TAG, "Failed to sync from DHT, continuing with local sync\n");
    } else {
        QGP_LOG_INFO(LOG_TAG, "Imported %d GEKs from DHT\n", imported);
    }

    // Then, sync to DHT (share local GEKs with other devices)
    int to_result = gek_sync_to_dht(dht_ctx, identity, kyber_pubkey, kyber_privkey,
                                     dilithium_pubkey, dilithium_privkey);

    if (to_result != 0) {
        QGP_LOG_WARN(LOG_TAG, "Failed to sync to DHT\n");
        // Non-fatal - we may have gotten GEKs from DHT
    }

    QGP_LOG_INFO(LOG_TAG, "Auto-sync complete (imported=%d)\n", imported);
    return 0;
}
