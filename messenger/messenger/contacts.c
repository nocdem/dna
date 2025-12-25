/*
 * DNA Messenger - Contacts Module Implementation
 */

#include "contacts.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../crypto/utils/qgp_platform.h"
#include "../crypto/utils/qgp_types.h"
#include "../crypto/utils/key_encryption.h"
#include "../dht/client/dht_contactlist.h"
#include "../dht/client/dht_singleton.h"
#include "../dht/core/dht_context.h"
#include "../database/contacts_db.h"
#include "../p2p/p2p_transport.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "MSG_CONTACTS"

// ============================================================================
// VALIDATION HELPERS
// ============================================================================

/**
 * Validate a fingerprint string (must be 128 hex characters)
 */
static bool is_valid_fingerprint(const char *fp) {
    if (!fp) return false;
    size_t len = strlen(fp);
    if (len != 128) return false;
    for (size_t i = 0; i < 128; i++) {
        char c = fp[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return false;
        }
    }
    return true;
}

// ============================================================================
// DHT CONTACT SYNCHRONIZATION
// ============================================================================

/**
 * Sync contacts to DHT (local → DHT)
 */
int messenger_sync_contacts_to_dht(messenger_context_t *ctx) {
    if (!ctx || !ctx->identity) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid context for DHT sync\n");
        return -1;
    }

    // Get DHT context from singleton (works even before P2P init)
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "DHT singleton not available\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Syncing contacts to DHT for '%s'\n", ctx->identity);

    // Load user's keys
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory\n");
        return -1;
    }

    // Load Kyber keypair (try encrypted if password available, fallback to unencrypted)
    char kyber_path[1024];
    snprintf(kyber_path, sizeof(kyber_path), "%s/%s/keys/%s.kem", data_dir, ctx->identity, ctx->identity);

    qgp_key_t *kyber_key = NULL;
    if (ctx->session_password) {
        // Try encrypted loading first
        if (qgp_key_load_encrypted(kyber_path, ctx->session_password, &kyber_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load encrypted Kyber key\n");
            return -1;
        }
    } else {
        // Try unencrypted loading
        if (qgp_key_load(kyber_path, &kyber_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load Kyber key\n");
            return -1;
        }
    }

    // Load Dilithium keypair (try encrypted if password available, fallback to unencrypted)
    char dilithium_path[1024];
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/%s/keys/%s.dsa", data_dir, ctx->identity, ctx->identity);

    qgp_key_t *dilithium_key = NULL;
    if (ctx->session_password) {
        if (qgp_key_load_encrypted(dilithium_path, ctx->session_password, &dilithium_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load encrypted Dilithium key\n");
            qgp_key_free(kyber_key);
            return -1;
        }
    } else {
        if (qgp_key_load(dilithium_path, &dilithium_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load Dilithium key\n");
            qgp_key_free(kyber_key);
            return -1;
        }
    }

    // Get contact list from local database
    contact_list_t *list = NULL;
    if (contacts_db_list(&list) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get contact list\n");
        qgp_key_free(kyber_key);
        qgp_key_free(dilithium_key);
        return -1;
    }

    // Convert to const char** array
    const char **contacts = NULL;
    if (list->count > 0) {
        contacts = malloc(list->count * sizeof(char*));
        if (!contacts) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to allocate contacts array\n");
            contacts_db_free_list(list);
            qgp_key_free(kyber_key);
            qgp_key_free(dilithium_key);
            return -1;
        }

        size_t valid_count = 0;
        for (size_t i = 0; i < list->count; i++) {
            if (is_valid_fingerprint(list->contacts[i].identity)) {
                contacts[valid_count++] = list->contacts[i].identity;
            } else {
                QGP_LOG_WARN(LOG_TAG, "Skipping invalid fingerprint in local DB (len=%zu)\n",
                             strlen(list->contacts[i].identity));
            }
        }
        // Update count to only valid entries
        list->count = valid_count;
    }

    // Publish to DHT
    int result = dht_contactlist_publish(
        dht_ctx,
        ctx->identity,
        contacts,
        list->count,
        kyber_key->public_key,
        kyber_key->private_key,
        dilithium_key->public_key,
        dilithium_key->private_key,
        0  // Use default 7-day TTL
    );

    // Save count before freeing list
    size_t contact_count = list->count;

    // Cleanup
    if (contacts) free(contacts);
    contacts_db_free_list(list);
    qgp_key_free(kyber_key);
    qgp_key_free(dilithium_key);

    if (result == 0) {
        QGP_LOG_INFO(LOG_TAG, "Successfully synced %zu contacts to DHT\n", contact_count);
    } else {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sync contacts to DHT\n");
    }

    return result;
}

/**
 * Sync contacts from DHT to local database (DHT is source of truth)
 * Replaces local contacts with DHT version
 */
int messenger_sync_contacts_from_dht(messenger_context_t *ctx) {
    if (!ctx || !ctx->identity) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid context for DHT sync\n");
        return -1;
    }

    // Get DHT context from singleton (works even before P2P init)
    dht_context_t *dht_ctx = dht_singleton_get();
    if (!dht_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "DHT singleton not available\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Syncing contacts from DHT for '%s'\n", ctx->identity);

    // Load user's keys
    const char *data_dir2 = qgp_platform_app_data_dir();
    if (!data_dir2) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory\n");
        return -1;
    }

    // Load Kyber private key for decryption (try encrypted if password available)
    char kyber_path2[1024];
    snprintf(kyber_path2, sizeof(kyber_path2), "%s/%s/keys/%s.kem", data_dir2, ctx->identity, ctx->identity);

    qgp_key_t *kyber_key = NULL;
    if (ctx->session_password) {
        if (qgp_key_load_encrypted(kyber_path2, ctx->session_password, &kyber_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load encrypted Kyber key\n");
            return -1;
        }
    } else {
        if (qgp_key_load(kyber_path2, &kyber_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load Kyber key\n");
            return -1;
        }
    }

    // Load Dilithium public key for signature verification (try encrypted if password available)
    char dilithium_path2[1024];
    snprintf(dilithium_path2, sizeof(dilithium_path2), "%s/%s/keys/%s.dsa", data_dir2, ctx->identity, ctx->identity);

    qgp_key_t *dilithium_key = NULL;
    if (ctx->session_password) {
        if (qgp_key_load_encrypted(dilithium_path2, ctx->session_password, &dilithium_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load encrypted Dilithium key\n");
            qgp_key_free(kyber_key);
            return -1;
        }
    } else {
        if (qgp_key_load(dilithium_path2, &dilithium_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to load Dilithium key\n");
            qgp_key_free(kyber_key);
            return -1;
        }
    }

    // Fetch from DHT
    char **contacts = NULL;
    size_t count = 0;

    int result = dht_contactlist_fetch(
        dht_ctx,
        ctx->identity,
        &contacts,
        &count,
        kyber_key->private_key,
        dilithium_key->public_key
    );

    qgp_key_free(kyber_key);
    qgp_key_free(dilithium_key);

    if (result == -2) {
        // Not found in DHT - this is OK for first time users
        QGP_LOG_INFO(LOG_TAG, "No contacts found in DHT (first time user)\n");
        return 0;
    }

    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to fetch contacts from DHT\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Fetched %zu contacts from DHT\n", count);

    // REPLACE mode: DHT is source of truth (deletions propagate)
    // With safety checks to prevent data loss from DHT failures

    // SAFETY CHECK 1: Verify DHT is actually connected
    if (!dht_context_is_ready(dht_ctx)) {
        QGP_LOG_ERROR(LOG_TAG, "SAFETY: DHT not ready, keeping local contacts\n");
        dht_contactlist_free_contacts(contacts, count);
        return -1;
    }

    // SAFETY CHECK 2: Get local contact count for comparison
    int local_count = contacts_db_count();
    if (local_count < 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get local contact count\n");
        dht_contactlist_free_contacts(contacts, count);
        return -1;
    }

    // SAFETY CHECK 3: Prevent deletion of contacts
    // If local has MORE contacts than DHT, abort (DHT is stale or incomplete)
    // Only sync from DHT if it has MORE or EQUAL contacts
    if (local_count > 0 && count < (size_t)local_count) {
        QGP_LOG_INFO(LOG_TAG, "SAFETY: Local has %d contacts but DHT has %zu\n", local_count, count);
        QGP_LOG_INFO(LOG_TAG, "SAFETY: DHT appears stale - using MERGE mode instead of REPLACE\n");

        // MERGE mode: only ADD contacts from DHT that don't exist locally
        size_t added = 0;
        for (size_t i = 0; i < count; i++) {
            if (!is_valid_fingerprint(contacts[i])) {
                QGP_LOG_WARN(LOG_TAG, "MERGE: Skipping invalid fingerprint from DHT (len=%zu)\n",
                             contacts[i] ? strlen(contacts[i]) : 0);
                continue;
            }
            if (!contacts_db_exists(contacts[i])) {
                if (contacts_db_add(contacts[i], NULL) == 0) {
                    added++;
                    QGP_LOG_INFO(LOG_TAG, "MERGE: Added new contact from DHT: %s\n", contacts[i]);
                }
            }
        }
        dht_contactlist_free_contacts(contacts, count);
        QGP_LOG_INFO(LOG_TAG, "MERGE sync complete: added %zu new contacts from DHT\n", added);
        return 0;
    }

    // DHT has equal or more contacts - safe to REPLACE
    QGP_LOG_INFO(LOG_TAG, "REPLACE sync: DHT has %zu contacts (local had %d)\n", count, local_count);

    if (contacts_db_clear_all() != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to clear local contacts\n");
        dht_contactlist_free_contacts(contacts, count);
        return -1;
    }

    // Add contacts from DHT
    size_t added = 0;
    for (size_t i = 0; i < count; i++) {
        if (!is_valid_fingerprint(contacts[i])) {
            QGP_LOG_WARN(LOG_TAG, "REPLACE: Skipping invalid fingerprint from DHT (len=%zu)\n",
                         contacts[i] ? strlen(contacts[i]) : 0);
            continue;
        }
        if (contacts_db_add(contacts[i], NULL) == 0) {
            added++;
        } else {
            QGP_LOG_ERROR(LOG_TAG, "Warning: Failed to add contact '%s'\n", contacts[i]);
        }
    }

    dht_contactlist_free_contacts(contacts, count);

    QGP_LOG_INFO(LOG_TAG, "REPLACE sync complete: %zu contacts from DHT (was %d local)\n",
           added, local_count);
    return 0;
}

/**
 * Auto-sync on first access: Try to fetch from DHT, if not found publish local
 * Called automatically when accessing contacts for the first time
 */
int messenger_contacts_auto_sync(messenger_context_t *ctx) {
    if (!ctx || !ctx->identity) {
        return -1;
    }

    static bool sync_attempted = false;
    if (sync_attempted) {
        return 0;  // Already attempted
    }
    sync_attempted = true;

    QGP_LOG_INFO(LOG_TAG, "Auto-sync: Checking DHT for existing contacts\n");

    // Try to sync from DHT first (DHT is source of truth)
    int result = messenger_sync_contacts_from_dht(ctx);

    if (result == 0) {
        QGP_LOG_INFO(LOG_TAG, "Auto-sync: Successfully synced from DHT\n");
        return 0;
    }

    // If DHT fetch failed or not found, publish local contacts to DHT
    QGP_LOG_INFO(LOG_TAG, "Auto-sync: Publishing local contacts to DHT\n");
    return messenger_sync_contacts_to_dht(ctx);
}
