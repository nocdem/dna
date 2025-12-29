/*
 * DNA Messenger - Initialization Module Implementation
 */

#include "init.h"
#include "identity.h"
#include "gsk.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include "../crypto/utils/qgp_platform.h"
#include "../crypto/utils/qgp_log.h"

#define LOG_TAG "MESSENGER"
#define LOG_TAG_DHT "DHT_IDENTITY"
#include "../crypto/utils/qgp_types.h"
#include "../message_backup.h"
#include "../database/keyserver_cache.h"
#include "../dht/client/dht_identity.h"
#include "../dht/client/dht_singleton.h"
#include "../crypto/utils/qgp_sha3.h"
#include "../crypto/utils/seed_storage.h"
#include "../crypto/bip39/bip39.h"
#include "../dht/client/dna_group_outbox.h"
#include "../dht/shared/dht_groups.h"

// Helper function to check if file exists
static bool file_exists(const char *path) {
    FILE *f = fopen(path, "r");
    if (f) {
        fclose(f);
        return true;
    }
    return false;
}

/**
 * Get the path to a key file (.dsa or .kem)
 * v0.3.0: Flat structure - always keys/identity.{dsa,kem}
 * fingerprint parameter kept for API compatibility but ignored
 */
static int init_find_key_path(const char *data_dir, const char *fingerprint,
                              const char *extension, char *path_out) {
    (void)fingerprint;  // Unused in v0.3.0 flat structure

    char test_path[512];
    snprintf(test_path, sizeof(test_path), "%s/keys/identity%s", data_dir, extension);

    if (file_exists(test_path)) {
        strncpy(path_out, test_path, 511);
        path_out[511] = '\0';
        return 0;
    }

    return -1;
}

/**
 * Resolve identity to fingerprint
 *
 * v0.3.0 Single-user model:
 * - If input is 128 hex chars → already a fingerprint, return as-is
 * - Otherwise → compute fingerprint from flat keys/identity.dsa
 *
 * @param identity_input: Fingerprint or any string (ignored in flat model)
 * @param fingerprint_out: Output buffer (129 bytes)
 * @return: 0 on success, -1 on error
 */
static int resolve_identity_to_fingerprint(const char *identity_input, char *fingerprint_out) {
    if (!identity_input || !fingerprint_out) {
        return -1;
    }

    // Check if input is already a fingerprint
    if (messenger_is_fingerprint(identity_input)) {
        strncpy(fingerprint_out, identity_input, 128);
        fingerprint_out[128] = '\0';
        return 0;
    }

    // v0.3.0: Flat structure - compute fingerprint from keys/identity.dsa
    const char *data_dir = qgp_platform_app_data_dir();
    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/keys/identity.dsa", data_dir);

    // Check if key file exists (no error message - expected for new identities)
    if (!file_exists(key_path)) {
        return -1;
    }

    // Compute fingerprint from key file
    // Note: messenger_compute_identity_fingerprint needs updating too
    if (messenger_compute_identity_fingerprint(NULL, fingerprint_out) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to compute fingerprint");
        return -1;
    }

    return 0;
}

// ============================================================================
// INITIALIZATION
// ============================================================================

messenger_context_t* messenger_init(const char *identity) {
    if (!identity) {
        QGP_LOG_ERROR(LOG_TAG, "Identity required");
        return NULL;
    }

    messenger_context_t *ctx = calloc(1, sizeof(messenger_context_t));
    if (!ctx) {
        return NULL;
    }

    // Set identity (input name or fingerprint)
    ctx->identity = strdup(identity);
    if (!ctx->identity) {
        free(ctx);
        return NULL;
    }

    // Compute canonical fingerprint (Phase 4: Fingerprint-First Identity)
    char fingerprint[129];
    if (resolve_identity_to_fingerprint(identity, fingerprint) == 0) {
        ctx->fingerprint = strdup(fingerprint);
        if (!ctx->fingerprint) {
            free(ctx->identity);
            free(ctx);
            return NULL;
        }
    } else {
        // Fingerprint resolution failed (key file not found or invalid)
        // For backward compatibility, continue without fingerprint
        ctx->fingerprint = NULL;
    }

    // Initialize SQLite local message storage (per-identity)
    // Use fingerprint (canonical) for consistent database path regardless of login method
    const char *db_identity = ctx->fingerprint ? ctx->fingerprint : identity;
    ctx->backup_ctx = message_backup_init(db_identity);
    if (!ctx->backup_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize SQLite message storage");
        free(ctx->fingerprint);
        free(ctx->identity);
        free(ctx);
        return NULL;
    }

    // Initialize GSK subsystem (Phase 13 - Group Symmetric Key)
    if (gsk_init(ctx->backup_ctx) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize GSK subsystem");
        message_backup_close(ctx->backup_ctx);
        free(ctx->identity);
        free(ctx);
        return NULL;
    }

    // Initialize Group Outbox subsystem (v0.10 - Feed pattern group messaging)
    dna_group_outbox_set_db(message_backup_get_db(ctx->backup_ctx));
    if (dna_group_outbox_db_init() != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize group outbox subsystem");
        message_backup_close(ctx->backup_ctx);
        free(ctx->identity);
        free(ctx);
        return NULL;
    }

    // Initialize DNA context
    ctx->dna_ctx = dna_context_new();
    if (!ctx->dna_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create DNA context");
        message_backup_close(ctx->backup_ctx);
        free(ctx->identity);
        free(ctx);
        return NULL;
    }

    // Initialize pubkey cache (in-memory)
    ctx->cache_count = 0;
    memset(ctx->cache, 0, sizeof(ctx->cache));

    // Initialize keyserver cache (SQLite persistent)
    if (keyserver_cache_init(NULL) != 0) {
        QGP_LOG_WARN(LOG_TAG, "Failed to initialize keyserver cache");
        // Non-fatal - continue without cache
    }

    // v0.3.0: Initialize DHT groups database (flat structure)
    char groups_db_path[512];
    snprintf(groups_db_path, sizeof(groups_db_path), "%s/db/groups.db", qgp_platform_app_data_dir());
    if (dht_groups_init(groups_db_path) != 0) {
        QGP_LOG_WARN(LOG_TAG, "Failed to initialize DHT groups database");
        // Non-fatal - continue without groups support
    }

    QGP_LOG_INFO(LOG_TAG, "Messenger initialized for '%s'", identity);

    return ctx;
}

void messenger_free(messenger_context_t *ctx) {
    if (!ctx) {
        return;
    }

    // Free pubkey cache
    for (int i = 0; i < ctx->cache_count; i++) {
        free(ctx->cache[i].identity);
        free(ctx->cache[i].signing_pubkey);
        free(ctx->cache[i].encryption_pubkey);
    }

    if (ctx->dna_ctx) {
        dna_context_free(ctx->dna_ctx);
    }

    if (ctx->backup_ctx) {
        message_backup_close(ctx->backup_ctx);
    }

    // Free fingerprint (Phase 4)
    if (ctx->fingerprint) {
        free(ctx->fingerprint);
    }

    // Securely clear and free session password (v0.2.17+)
    if (ctx->session_password) {
        memset(ctx->session_password, 0, strlen(ctx->session_password));
        free(ctx->session_password);
    }

    // DON'T cleanup global keyserver cache - it's shared across all contexts
    // Only cleanup on app shutdown, not on temporary context free
    // keyserver_cache_cleanup();

    free(ctx->identity);
    free(ctx);
}

/**
 * Set session password for encrypted key operations (v0.2.17+)
 */
void messenger_set_session_password(messenger_context_t *ctx, const char *password) {
    if (!ctx) return;

    // Clear existing password if any
    if (ctx->session_password) {
        memset(ctx->session_password, 0, strlen(ctx->session_password));
        free(ctx->session_password);
        ctx->session_password = NULL;
    }

    // Set new password
    if (password) {
        ctx->session_password = strdup(password);
    }
}

/**
 * Load DHT identity and reinitialize DHT singleton with permanent identity
 *
 * v0.3.0+: DHT identity is derived deterministically from BIP39 master seed.
 * No network dependency - same seed always produces same DHT identity.
 *
 * Load order:
 * 1. Try cached dht_identity.bin (fast path)
 * 2. Derive from mnemonic.enc → master_seed → dht_seed (restore path)
 */
int messenger_load_dht_identity(const char *fingerprint) {
    if (!fingerprint || strlen(fingerprint) != 128) {
        QGP_LOG_ERROR(LOG_TAG_DHT, "Invalid fingerprint");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG_DHT, "Loading DHT identity for %.16s...", fingerprint);

    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG_DHT, "Cannot get data directory");
        return -1;
    }

    // v0.3.0: Flat structure - all files in root data_dir
    dht_identity_t *dht_identity = NULL;

    // Method 1: Try to load cached dht_identity.bin (fast path)
    char dht_id_path[512];
    snprintf(dht_id_path, sizeof(dht_id_path), "%s/dht_identity.bin", data_dir);

    FILE *f = fopen(dht_id_path, "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        size_t file_size = ftell(f);
        fseek(f, 0, SEEK_SET);

        uint8_t *buffer = malloc(file_size);
        if (buffer && fread(buffer, 1, file_size, f) == file_size) {
            if (dht_identity_import_from_buffer(buffer, file_size, &dht_identity) == 0) {
                QGP_LOG_INFO(LOG_TAG_DHT, "Loaded from cached dht_identity.bin");
            }
            free(buffer);
        }
        fclose(f);
    }

    // Method 2: Derive from mnemonic if not cached (restore path)
    if (!dht_identity) {
        QGP_LOG_INFO(LOG_TAG_DHT, "Cached identity not found, deriving from mnemonic...");

        // Load Kyber private key (for mnemonic decryption)
        char kyber_path[512];
        if (init_find_key_path(data_dir, fingerprint, ".kem", kyber_path) != 0) {
            QGP_LOG_ERROR(LOG_TAG_DHT, "Kyber key not found for fingerprint: %.16s...", fingerprint);
            return -1;
        }

        qgp_key_t *kyber_key = NULL;
        if (qgp_key_load(kyber_path, &kyber_key) != 0 || !kyber_key) {
            QGP_LOG_ERROR(LOG_TAG_DHT, "Failed to load Kyber key from %s", kyber_path);
            return -1;
        }

        // Load and decrypt mnemonic (v0.3.0: flat structure - mnemonic.enc in root data_dir)
        char mnemonic[512] = {0};
        if (mnemonic_storage_load(mnemonic, sizeof(mnemonic),
                                   kyber_key->private_key, data_dir) != 0) {
            QGP_LOG_ERROR(LOG_TAG_DHT, "Failed to load mnemonic - cannot derive DHT identity");
            qgp_key_free(kyber_key);
            return -1;
        }

        qgp_key_free(kyber_key);

        // Convert mnemonic to master seed
        uint8_t master_seed[64];
        if (bip39_mnemonic_to_seed(mnemonic, "", master_seed) != 0) {
            QGP_LOG_ERROR(LOG_TAG_DHT, "Failed to convert mnemonic to master seed");
            memset(mnemonic, 0, sizeof(mnemonic));
            return -1;
        }
        memset(mnemonic, 0, sizeof(mnemonic));

        // Derive dht_seed = SHA3-512(master_seed + "dht_identity")[0:32]
        // Use SHA3-512 truncated to 32 bytes (cryptographically sound)
        uint8_t dht_seed[32];
        uint8_t full_hash[64];
        uint8_t seed_input[64 + 12];  // 64-byte master_seed + "dht_identity" (12 bytes)
        memcpy(seed_input, master_seed, 64);
        memcpy(seed_input + 64, "dht_identity", 12);
        memset(master_seed, 0, sizeof(master_seed));

        if (qgp_sha3_512(seed_input, sizeof(seed_input), full_hash) != 0) {
            QGP_LOG_ERROR(LOG_TAG_DHT, "Failed to derive DHT seed");
            memset(seed_input, 0, sizeof(seed_input));
            return -1;
        }
        memset(seed_input, 0, sizeof(seed_input));

        // Truncate to 32 bytes for DHT seed
        memcpy(dht_seed, full_hash, 32);
        memset(full_hash, 0, sizeof(full_hash));

        // Generate DHT identity from derived seed
        if (dht_identity_generate_from_seed(dht_seed, &dht_identity) != 0) {
            QGP_LOG_ERROR(LOG_TAG_DHT, "Failed to generate DHT identity from seed");
            memset(dht_seed, 0, sizeof(dht_seed));
            return -1;
        }
        memset(dht_seed, 0, sizeof(dht_seed));

        QGP_LOG_INFO(LOG_TAG_DHT, "Derived DHT identity from mnemonic (deterministic)");

        // Cache for next time
        uint8_t *dht_id_buffer = NULL;
        size_t dht_id_size = 0;
        if (dht_identity_export_to_buffer(dht_identity, &dht_id_buffer, &dht_id_size) == 0) {
            FILE *cache_f = fopen(dht_id_path, "wb");
            if (cache_f) {
                fwrite(dht_id_buffer, 1, dht_id_size, cache_f);
                fclose(cache_f);
                QGP_LOG_INFO(LOG_TAG_DHT, "Cached DHT identity for future loads");
            }
            free(dht_id_buffer);
        }
    }

    // Reinitialize DHT singleton with permanent identity
    QGP_LOG_INFO(LOG_TAG_DHT, ">>> DHT REINIT START <<<");

    // Cleanup old DHT (ephemeral identity)
    dht_singleton_cleanup();

    // Init with permanent identity
    if (dht_singleton_init_with_identity(dht_identity) != 0) {
        QGP_LOG_ERROR(LOG_TAG_DHT, "Failed to reinitialize DHT singleton");
        dht_identity_free(dht_identity);
        return -1;
    }

    // Don't free dht_identity here - it's owned by DHT singleton now
    QGP_LOG_INFO(LOG_TAG_DHT, ">>> DHT REINIT COMPLETE <<<");

    return 0;
}
