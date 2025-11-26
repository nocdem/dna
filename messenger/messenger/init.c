/*
 * DNA Messenger - Initialization Module Implementation
 */

#include "init.h"
#include "identity.h"
#include "gsk.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../crypto/utils/qgp_platform.h"
#include "../crypto/utils/qgp_types.h"
#include "../message_backup.h"
#include "../database/keyserver_cache.h"
#include "../dht/client/dht_identity_backup.h"
#include "../dht/client/dht_singleton.h"
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
 * Resolve identity to fingerprint
 *
 * This function supports the transition to fingerprint-first identities:
 * - If input is 128 hex chars → already a fingerprint, return as-is
 * - If input is a name → check if key file exists, compute fingerprint
 *
 * @param identity_input: Name or fingerprint
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

    // Input is a name, compute fingerprint from key file
    const char *home = qgp_platform_home_dir();
    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/.dna/%s.dsa", home, identity_input);

    // Check if key file exists (no error message - expected for new identities)
    if (!file_exists(key_path)) {
        return -1;
    }

    // Compute fingerprint from key file
    if (messenger_compute_identity_fingerprint(identity_input, fingerprint_out) != 0) {
        fprintf(stderr, "Error: Failed to compute fingerprint for '%s'\n", identity_input);
        return -1;
    }

    return 0;
}

// ============================================================================
// INITIALIZATION
// ============================================================================

messenger_context_t* messenger_init(const char *identity) {
    if (!identity) {
        fprintf(stderr, "Error: Identity required\n");
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
        fprintf(stderr, "Error: Failed to initialize SQLite message storage\n");
        free(ctx->fingerprint);
        free(ctx->identity);
        free(ctx);
        return NULL;
    }

    // Initialize GSK subsystem (Phase 13 - Group Symmetric Key)
    if (gsk_init(ctx->backup_ctx) != 0) {
        fprintf(stderr, "Error: Failed to initialize GSK subsystem\n");
        message_backup_close(ctx->backup_ctx);
        free(ctx->identity);
        free(ctx);
        return NULL;
    }

    // Initialize DNA context
    ctx->dna_ctx = dna_context_new();
    if (!ctx->dna_ctx) {
        fprintf(stderr, "Error: Failed to create DNA context\n");
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
        fprintf(stderr, "Warning: Failed to initialize keyserver cache\n");
        // Non-fatal - continue without cache
    }

    // Initialize DHT groups database (per-identity)
    char groups_db_path[512];
    snprintf(groups_db_path, sizeof(groups_db_path), "%s/.dna/%s_groups.db", getenv("HOME"), identity);
    if (dht_groups_init(groups_db_path) != 0) {
        fprintf(stderr, "Warning: Failed to initialize DHT groups database\n");
        // Non-fatal - continue without groups support
    }

    printf("✓ Messenger initialized for '%s'\n", identity);
    printf("✓ SQLite database: ~/.dna/messages.db\n");

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

    // DON'T cleanup global keyserver cache - it's shared across all contexts
    // Only cleanup on app shutdown, not on temporary context free
    // keyserver_cache_cleanup();

    free(ctx->identity);
    free(ctx);
}

/**
 * Load DHT identity and reinitialize DHT singleton with permanent identity
 */
int messenger_load_dht_identity(const char *fingerprint) {
    if (!fingerprint || strlen(fingerprint) != 128) {
        fprintf(stderr, "[DHT Identity] Invalid fingerprint\n");
        return -1;
    }

    printf("[DHT Identity] Loading DHT identity for %s...\n", fingerprint);

    // Load Kyber1024 private key (for decryption)
    const char *home = qgp_platform_home_dir();
    if (!home) {
        fprintf(stderr, "[DHT Identity] Cannot get home directory\n");
        return -1;
    }

    char kyber_path[512];
    snprintf(kyber_path, sizeof(kyber_path), "%s/.dna/%s.kem", home, fingerprint);

    qgp_key_t *kyber_key = NULL;
    if (qgp_key_load(kyber_path, &kyber_key) != 0 || !kyber_key) {
        fprintf(stderr, "[DHT Identity] Failed to load Kyber key from %s\n", kyber_path);
        return -1;
    }

    if (kyber_key->private_key_size != 3168) {
        fprintf(stderr, "[DHT Identity] Invalid Kyber private key size: %zu (expected 3168)\n",
                kyber_key->private_key_size);
        qgp_key_free(kyber_key);
        return -1;
    }

    // Try to load from local file first
    dht_identity_t *dht_identity = NULL;
    if (dht_identity_load_from_local(fingerprint, kyber_key->private_key, &dht_identity) == 0) {
        printf("[DHT Identity] ✓ Loaded from local file\n");
    } else {
        printf("[DHT Identity] Local file not found, fetching from DHT...\n");

        // Get DHT context (for fetching)
        dht_context_t *dht_ctx = dht_singleton_get();
        if (!dht_ctx) {
            fprintf(stderr, "[DHT Identity] DHT not initialized, cannot fetch from DHT\n");
            qgp_key_free(kyber_key);
            return -1;
        }

        // Try to fetch from DHT
        if (dht_identity_fetch_from_dht(fingerprint, kyber_key->private_key, dht_ctx, &dht_identity) != 0) {
            fprintf(stderr, "[DHT Identity] Failed to fetch from DHT\n");
            fprintf(stderr, "[DHT Identity] No DHT identity found (local or DHT)\n");
            fprintf(stderr, "[DHT Identity] Warning: DHT operations may accumulate values\n");
            qgp_key_free(kyber_key);
            return -1;
        }

        printf("[DHT Identity] ✓ Fetched from DHT and saved locally\n");
    }

    qgp_key_free(kyber_key);

    // Reinitialize DHT singleton with permanent identity
    printf("[DHT Identity] Reinitializing DHT with permanent identity...\n");

    // Cleanup old DHT (ephemeral identity)
    dht_singleton_cleanup();

    // Init with permanent identity
    if (dht_singleton_init_with_identity(dht_identity) != 0) {
        fprintf(stderr, "[DHT Identity] Failed to reinitialize DHT singleton\n");
        dht_identity_free(dht_identity);
        return -1;
    }

    // Don't free dht_identity here - it's owned by DHT singleton now
    printf("[DHT Identity] ✓ DHT reinitialized with permanent identity\n");

    return 0;
}
