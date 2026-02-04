/*
 * DNA Messenger - Initialization Module Implementation
 */

#include "init.h"
#include "identity.h"
#include "gek.h"
#include "groups.h"
#include "group_database.h"
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
#include "../database/group_invitations.h"
#include "../database/addressbook_db.h"
#include "../database/feed_subscriptions_db.h"
#include "../messenger_transport.h"

/**
 * Get the path to a key file (.dsa or .kem)
 * v0.3.0: Flat structure - always keys/identity.{dsa,kem}
 *
 * Shared implementation for all messenger modules.
 */
int messenger_find_key_path(const char *data_dir, const char *fingerprint,
                            const char *extension, char *path_out) {
    (void)fingerprint;  // Unused in v0.3.0 flat structure

    char test_path[512];
    snprintf(test_path, sizeof(test_path), "%s/keys/identity%s", data_dir, extension);

    if (qgp_platform_file_exists(test_path)) {
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
    if (!qgp_platform_file_exists(key_path)) {
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

/**
 * Prepare DHT connection from mnemonic (before identity creation)
 *
 * v0.3.0+: Called when user enters seed phrase and presses "Next".
 * Starts DHT connection early so it's ready when identity is created.
 *
 * Flow:
 * 1. User enters seed → presses Next
 * 2. This function starts DHT (non-blocking)
 * 3. User enters nickname (DHT connects in background)
 * 4. User presses Create → DHT is ready → name registration succeeds
 */
int messenger_prepare_dht_from_mnemonic(const char *mnemonic) {
    if (!mnemonic || strlen(mnemonic) < 10) {
        QGP_LOG_ERROR(LOG_TAG_DHT, "Invalid mnemonic for DHT preparation");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG_DHT, "Preparing DHT connection from mnemonic...");

    // Convert mnemonic to master seed
    uint8_t master_seed[64];
    if (bip39_mnemonic_to_seed(mnemonic, "", master_seed) != 0) {
        QGP_LOG_ERROR(LOG_TAG_DHT, "Failed to convert mnemonic to master seed");
        return -1;
    }

    // Derive dht_seed = SHA3-512(master_seed + "dht_identity")[0:32]
    uint8_t dht_seed[32];
    uint8_t full_hash[64];
    uint8_t seed_input[64 + 12];
    memcpy(seed_input, master_seed, 64);
    memcpy(seed_input + 64, "dht_identity", 12);
    qgp_secure_memzero(master_seed, sizeof(master_seed));

    if (qgp_sha3_512(seed_input, sizeof(seed_input), full_hash) != 0) {
        QGP_LOG_ERROR(LOG_TAG_DHT, "Failed to derive DHT seed");
        qgp_secure_memzero(seed_input, sizeof(seed_input));
        return -1;
    }
    qgp_secure_memzero(seed_input, sizeof(seed_input));

    memcpy(dht_seed, full_hash, 32);
    qgp_secure_memzero(full_hash, sizeof(full_hash));

    // Generate DHT identity from derived seed
    dht_identity_t *dht_identity = NULL;
    if (dht_identity_generate_from_seed(dht_seed, &dht_identity) != 0) {
        QGP_LOG_ERROR(LOG_TAG_DHT, "Failed to generate DHT identity from seed");
        qgp_secure_memzero(dht_seed, sizeof(dht_seed));
        return -1;
    }
    qgp_secure_memzero(dht_seed, sizeof(dht_seed));

    QGP_LOG_INFO(LOG_TAG_DHT, "Derived DHT identity from mnemonic (early preparation)");

    // Cleanup any existing DHT
    dht_singleton_cleanup();

    // Start DHT with derived identity (non-blocking - bootstraps in background)
    if (dht_singleton_init_with_identity(dht_identity) != 0) {
        QGP_LOG_ERROR(LOG_TAG_DHT, "Failed to initialize DHT with derived identity");
        dht_identity_free(dht_identity);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG_DHT, "DHT connection started (bootstrapping in background)");
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

    // Initialize group database (separate from messages.db)
    if (group_database_init() == NULL) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize group database");
        message_backup_close(ctx->backup_ctx);
        free(ctx->fingerprint);
        free(ctx->identity);
        free(ctx);
        return NULL;
    }

    // Initialize GEK subsystem (Group Encryption Key)
    if (gek_init(NULL) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize GEK subsystem");
        group_database_close(group_database_get_instance());
        message_backup_close(ctx->backup_ctx);
        free(ctx->identity);
        free(ctx);
        return NULL;
    }

    // Initialize Groups subsystem (sets groups_db for groups_import_all)
    if (groups_init(NULL) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to initialize groups subsystem");
        group_database_close(group_database_get_instance());
        message_backup_close(ctx->backup_ctx);
        free(ctx->fingerprint);
        free(ctx->identity);
        free(ctx);
        return NULL;
    }

    // Initialize Group Outbox subsystem (v0.10 - Feed pattern group messaging)
    // Use groups.db (not messages.db) - group_messages table is in groups.db
    group_database_context_t *grp_db_ctx = group_database_get_instance();
    if (grp_db_ctx) {
        dna_group_outbox_set_db(group_database_get_db(grp_db_ctx));
    }
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
    QGP_LOG_WARN(LOG_TAG, ">>> dht_groups_init START path=%s", groups_db_path);
    if (dht_groups_init(groups_db_path) != 0) {
        QGP_LOG_WARN(LOG_TAG, "Failed to initialize DHT groups database");
        // Non-fatal - continue without groups support
    }
    QGP_LOG_WARN(LOG_TAG, ">>> dht_groups_init DONE");

    QGP_LOG_INFO(LOG_TAG, "Messenger initialized for '%s'", identity);

    return ctx;
}

void messenger_free(messenger_context_t *ctx) {
    if (!ctx) {
        return;
    }

    // Shutdown transport first (v0.4.66 - fix memory leak)
    messenger_transport_shutdown(ctx);

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

    // v0.6.117: Clean up all global singletons to prevent stale pointers on Android
    // (engine destroy/create cycles leave globals pointing to closed connections)

    // 1. NULL borrowed DB pointers BEFORE closing group_database
    gek_cleanup();
    groups_cleanup();
    dna_group_outbox_cleanup();

    // 2. Close group database (v0.4.63 - separate from messages.db)
    group_database_close(group_database_get_instance());

    // 3. Close singletons that own their own DB connections
    dht_groups_cleanup();
    group_invitations_cleanup();
    addressbook_db_close();
    feed_subscriptions_db_close();

    // Free fingerprint (Phase 4)
    if (ctx->fingerprint) {
        free(ctx->fingerprint);
    }

    // Securely clear and free session password (v0.2.17+)
    if (ctx->session_password) {
        qgp_secure_memzero(ctx->session_password, strlen(ctx->session_password));
        free(ctx->session_password);
    }

    // DON'T cleanup global keyserver cache - it's shared across all contexts
    // Only cleanup on app shutdown, not on temporary context free
    // keyserver_cache_cleanup();

    free(ctx->identity);
    free(ctx);
}

message_backup_context_t* messenger_get_backup_ctx(messenger_context_t *ctx) {
    if (!ctx) return NULL;
    return ctx->backup_ctx;
}

/**
 * Set session password for encrypted key operations (v0.2.17+)
 */
void messenger_set_session_password(messenger_context_t *ctx, const char *password) {
    if (!ctx) return;

    // Clear existing password if any
    if (ctx->session_password) {
        qgp_secure_memzero(ctx->session_password, strlen(ctx->session_password));
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
        if (messenger_find_key_path(data_dir, fingerprint, ".kem", kyber_path) != 0) {
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
            qgp_secure_memzero(mnemonic, sizeof(mnemonic));
            return -1;
        }
        qgp_secure_memzero(mnemonic, sizeof(mnemonic));

        // Derive dht_seed = SHA3-512(master_seed + "dht_identity")[0:32]
        // Use SHA3-512 truncated to 32 bytes (cryptographically sound)
        uint8_t dht_seed[32];
        uint8_t full_hash[64];
        uint8_t seed_input[64 + 12];  // 64-byte master_seed + "dht_identity" (12 bytes)
        memcpy(seed_input, master_seed, 64);
        memcpy(seed_input + 64, "dht_identity", 12);
        qgp_secure_memzero(master_seed, sizeof(master_seed));

        if (qgp_sha3_512(seed_input, sizeof(seed_input), full_hash) != 0) {
            QGP_LOG_ERROR(LOG_TAG_DHT, "Failed to derive DHT seed");
            qgp_secure_memzero(seed_input, sizeof(seed_input));
            return -1;
        }
        qgp_secure_memzero(seed_input, sizeof(seed_input));

        // Truncate to 32 bytes for DHT seed
        memcpy(dht_seed, full_hash, 32);
        qgp_secure_memzero(full_hash, sizeof(full_hash));

        // Generate DHT identity from derived seed
        if (dht_identity_generate_from_seed(dht_seed, &dht_identity) != 0) {
            QGP_LOG_ERROR(LOG_TAG_DHT, "Failed to generate DHT identity from seed");
            qgp_secure_memzero(dht_seed, sizeof(dht_seed));
            return -1;
        }
        qgp_secure_memzero(dht_seed, sizeof(dht_seed));

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

    // Initialize DHT singleton with permanent identity
    QGP_LOG_INFO(LOG_TAG_DHT, ">>> DHT INIT START <<<");

    // Cleanup old DHT (ephemeral identity)
    dht_singleton_cleanup();

    // Init with permanent identity
    if (dht_singleton_init_with_identity(dht_identity) != 0) {
        QGP_LOG_ERROR(LOG_TAG_DHT, "Failed to reinitialize DHT singleton");
        dht_identity_free(dht_identity);
        return -1;
    }

    // Don't free dht_identity here - it's owned by DHT singleton now
    QGP_LOG_INFO(LOG_TAG_DHT, ">>> DHT INIT COMPLETE <<<");

    return 0;
}

/**
 * Load DHT identity and create engine-owned DHT context (v0.6.0+)
 *
 * Same as messenger_load_dht_identity() but returns a new DHT context
 * instead of storing in global singleton.
 */
int messenger_load_dht_identity_for_engine(const char *fingerprint, dht_context_t **ctx_out) {
    if (!fingerprint || strlen(fingerprint) != 128 || !ctx_out) {
        QGP_LOG_ERROR(LOG_TAG_DHT, "Invalid params for engine DHT identity");
        return -1;
    }

    *ctx_out = NULL;
    QGP_LOG_INFO(LOG_TAG_DHT, "Loading DHT identity for engine (%.16s...)", fingerprint);

    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG_DHT, "Cannot get data directory");
        return -1;
    }

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

    // Method 2: Derive from mnemonic if not cached
    if (!dht_identity) {
        QGP_LOG_INFO(LOG_TAG_DHT, "Deriving DHT identity from mnemonic...");

        char kyber_path[512];
        if (messenger_find_key_path(data_dir, fingerprint, ".kem", kyber_path) != 0) {
            QGP_LOG_ERROR(LOG_TAG_DHT, "Kyber key not found");
            return -1;
        }

        qgp_key_t *kyber_key = NULL;
        if (qgp_key_load(kyber_path, &kyber_key) != 0 || !kyber_key) {
            QGP_LOG_ERROR(LOG_TAG_DHT, "Failed to load Kyber key");
            return -1;
        }

        char mnemonic[512] = {0};
        if (mnemonic_storage_load(mnemonic, sizeof(mnemonic),
                                   kyber_key->private_key, data_dir) != 0) {
            QGP_LOG_ERROR(LOG_TAG_DHT, "Failed to load mnemonic");
            qgp_key_free(kyber_key);
            return -1;
        }
        qgp_key_free(kyber_key);

        uint8_t master_seed[64];
        if (bip39_mnemonic_to_seed(mnemonic, "", master_seed) != 0) {
            QGP_LOG_ERROR(LOG_TAG_DHT, "Failed to convert mnemonic");
            qgp_secure_memzero(mnemonic, sizeof(mnemonic));
            return -1;
        }
        qgp_secure_memzero(mnemonic, sizeof(mnemonic));

        uint8_t dht_seed[32];
        uint8_t full_hash[64];
        uint8_t seed_input[64 + 12];
        memcpy(seed_input, master_seed, 64);
        memcpy(seed_input + 64, "dht_identity", 12);
        qgp_secure_memzero(master_seed, sizeof(master_seed));

        if (qgp_sha3_512(seed_input, sizeof(seed_input), full_hash) != 0) {
            qgp_secure_memzero(seed_input, sizeof(seed_input));
            return -1;
        }
        qgp_secure_memzero(seed_input, sizeof(seed_input));

        memcpy(dht_seed, full_hash, 32);
        qgp_secure_memzero(full_hash, sizeof(full_hash));

        if (dht_identity_generate_from_seed(dht_seed, &dht_identity) != 0) {
            qgp_secure_memzero(dht_seed, sizeof(dht_seed));
            return -1;
        }
        qgp_secure_memzero(dht_seed, sizeof(dht_seed));

        QGP_LOG_INFO(LOG_TAG_DHT, "Derived DHT identity from mnemonic");

        // Cache for next time
        uint8_t *dht_id_buffer = NULL;
        size_t dht_id_size = 0;
        if (dht_identity_export_to_buffer(dht_identity, &dht_id_buffer, &dht_id_size) == 0) {
            FILE *cache_f = fopen(dht_id_path, "wb");
            if (cache_f) {
                fwrite(dht_id_buffer, 1, dht_id_size, cache_f);
                fclose(cache_f);
            }
            free(dht_id_buffer);
        }
    }

    // Create engine-owned DHT context (NOT singleton)
    QGP_LOG_INFO(LOG_TAG_DHT, ">>> ENGINE DHT INIT START <<<");

    *ctx_out = dht_create_context_with_identity(dht_identity);
    if (!*ctx_out) {
        QGP_LOG_ERROR(LOG_TAG_DHT, "Failed to create engine DHT context");
        dht_identity_free(dht_identity);
        return -1;
    }

    // Don't free dht_identity - owned by DHT context now
    QGP_LOG_INFO(LOG_TAG_DHT, ">>> ENGINE DHT INIT COMPLETE <<<");

    return 0;
}
