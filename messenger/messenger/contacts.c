/*
 * DNA Connect - Contacts Module Implementation
 */

#include "contacts.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/qgp_types.h"
#include "crypto/key/key_encryption.h"
#include "../dht/client/dht_contactlist.h"
#include "../dht/keyserver/keyserver_core.h"
#include "../database/contacts_db.h"
#include "../transport/transport.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "MSG_CONTACTS"

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

    QGP_LOG_WARN(LOG_TAG, "[CONTACTLIST_PUBLISH] messenger_sync_contacts_to_dht called for %.16s...\n", ctx->identity);

    // Load user's keys
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory\n");
        return -1;
    }

    // Load Kyber keypair (try encrypted if password available, fallback to unencrypted)
    // v0.3.0: Flat structure - keys/identity.kem
    char kyber_path[1024];
    snprintf(kyber_path, sizeof(kyber_path), "%s/keys/identity.kem", data_dir);

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
    // v0.3.0: Flat structure - keys/identity.dsa
    char dilithium_path[1024];
    snprintf(dilithium_path, sizeof(dilithium_path), "%s/keys/identity.dsa", data_dir);

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

    // Convert to const char** and salt arrays
    const char **contacts = NULL;
    const uint8_t **salts = NULL;
    uint8_t *salt_storage = NULL;
    if (list->count > 0) {
        contacts = malloc(list->count * sizeof(char*));
        salts = (const uint8_t **)calloc(list->count, sizeof(uint8_t*));
        salt_storage = calloc(list->count, 32);
        if (!contacts || !salts || !salt_storage) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to allocate contacts/salts arrays\n");
            free(contacts);
            free(salts);
            free(salt_storage);
            contacts_db_free_list(list);
            qgp_key_free(kyber_key);
            qgp_key_free(dilithium_key);
            return -1;
        }

        size_t valid_count = 0;
        for (size_t i = 0; i < list->count; i++) {
            if (is_valid_fingerprint(list->contacts[i].identity)) {
                contacts[valid_count] = list->contacts[i].identity;
                /* Copy salt from contact entry if present */
                if (list->contacts[i].has_dht_salt) {
                    memcpy(salt_storage + (valid_count * 32),
                           list->contacts[i].dht_salt, 32);
                    salts[valid_count] = salt_storage + (valid_count * 32);
                } else {
                    salts[valid_count] = NULL;
                }
                valid_count++;
            } else {
                QGP_LOG_WARN(LOG_TAG, "Skipping invalid fingerprint in local DB (len=%zu)\n",
                             strlen(list->contacts[i].identity));
            }
        }
        // Update count to only valid entries
        list->count = valid_count;
    }

    // Publish to DHT (v2 with salts)
    int result = dht_contactlist_publish(
        ctx->identity,
        contacts,
        list->count,
        salts,
        kyber_key->public_key,
        kyber_key->private_key,
        dilithium_key->public_key,
        dilithium_key->private_key,
        0  // Use default 7-day TTL
    );

    // Save count before freeing list
    size_t contact_count = list->count;

    // Cleanup
    free(contacts);
    free(salts);
    free(salt_storage);
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

    QGP_LOG_INFO(LOG_TAG, "Syncing contacts from DHT for '%s'\n", ctx->identity);

    // Load user's keys
    const char *data_dir2 = qgp_platform_app_data_dir();
    if (!data_dir2) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory\n");
        return -1;
    }

    // Load Kyber private key for decryption (try encrypted if password available)
    // v0.3.0: Flat structure - keys/identity.kem
    char kyber_path2[1024];
    snprintf(kyber_path2, sizeof(kyber_path2), "%s/keys/identity.kem", data_dir2);

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
    // v0.3.0: Flat structure - keys/identity.dsa
    char dilithium_path2[1024];
    snprintf(dilithium_path2, sizeof(dilithium_path2), "%s/keys/identity.dsa", data_dir2);

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

    // Fetch from DHT (v2 returns salts alongside fingerprints)
    char **contacts = NULL;
    uint8_t **salts = NULL;
    size_t count = 0;

    int result = dht_contactlist_fetch(
        ctx->identity,
        &contacts,
        &count,
        &salts,
        kyber_key->private_key,
        dilithium_key->public_key
    );

    qgp_key_free(kyber_key);
    qgp_key_free(dilithium_key);

    if (result == -2) {
        // Not found in DHT - check if we have local contacts to publish
        int local_count = contacts_db_count();
        if (local_count > 0) {
            QGP_LOG_WARN(LOG_TAG, "[CONTACTLIST_PUBLISH] sync_from_dht: DHT empty, publishing %d local contacts\n", local_count);
            return messenger_sync_contacts_to_dht(ctx);
        }
        QGP_LOG_INFO(LOG_TAG, "No contacts in DHT or local (first time user)\n");
        return 0;
    }

    if (result != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to fetch contacts from DHT\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Fetched %zu contacts from DHT\n", count);

    // REPLACE mode: DHT is source of truth (deletions propagate)
    // With invariant guard to prevent data loss from empty DHT responses

    int local_count = contacts_db_count();
    if (local_count < 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get local contact count\n");
        dht_contactlist_free_contacts(contacts, count);
        dht_contactlist_free_salts(salts, count);
        return -1;
    }

    // INVARIANT GUARD: A user with local contacts should never have them wiped
    // by an empty DHT response. count==0 with local data indicates DHT unavailability.
    if (count == 0 && local_count > 0) {
        QGP_LOG_WARN(LOG_TAG, "[SYNC] DHT returned 0 contacts but local has %d — publishing local to DHT\n", local_count);
        dht_contactlist_free_contacts(contacts, count);
        dht_contactlist_free_salts(salts, count);
        return messenger_sync_contacts_to_dht(ctx);
    }

    // MERGE SYNC: DHT is primary, but contacts with established salts are protected.
    // A contact with a dht_salt was added via the contact request flow (cryptographic
    // handshake) and must NEVER be removed by a stale DHT contactlist snapshot.
    // The DHT contactlist can lag behind due to publish timing — removing salted
    // contacts causes a destructive cycle: remove → re-add without salt → key mismatch.
    QGP_LOG_INFO(LOG_TAG, "DIFF sync: DHT has %zu contacts (local had %d)\n", count, local_count);

    // Snapshot local contacts for diff
    contact_list_t *local_list = NULL;
    contacts_db_list(&local_list);

    // Phase 1: Remove contacts that are in local but NOT in DHT.
    // PROTECT contacts that have a dht_salt — they were established via contact
    // request exchange and the DHT contactlist may simply not have been republished yet.
    size_t removed = 0;
    size_t protected = 0;
    bool need_republish = false;
    if (local_list && local_list->count > 0) {
        for (size_t i = 0; i < local_list->count; i++) {
            const char *local_id = local_list->contacts[i].identity;
            bool found_in_dht = false;
            for (size_t j = 0; j < count; j++) {
                if (contacts[j] && strcmp(local_id, contacts[j]) == 0) {
                    found_in_dht = true;
                    break;
                }
            }
            if (!found_in_dht) {
                if (local_list->contacts[i].has_dht_salt) {
                    // Contact has established salt from contact request flow — keep it
                    QGP_LOG_WARN(LOG_TAG, "DIFF: Protecting salted contact %.20s... (not in DHT contactlist)\n",
                                 local_id);
                    protected++;
                    need_republish = true;  // DHT contactlist is stale, republish
                } else {
                    contacts_db_remove(local_id);
                    removed++;
                }
            }
        }
    }

    // Phase 2: Add new contacts from DHT, update salts for existing
    size_t added = 0;
    size_t salts_updated = 0;
    for (size_t i = 0; i < count; i++) {
        if (!is_valid_fingerprint(contacts[i])) {
            QGP_LOG_WARN(LOG_TAG, "DIFF: Skipping invalid fingerprint from DHT (len=%zu)\n",
                         contacts[i] ? strlen(contacts[i]) : 0);
            continue;
        }

        if (contacts_db_exists(contacts[i])) {
            // Already exists — do NOT overwrite salt from DHT sync.
            // Salt is established during contact request exchange and must not
            // be replaced. DHT contact list stores OUR salt for each contact,
            // but reading messages requires THEIR salt (set during request).
            // Overwriting here causes key mismatch → messages not found.
            (void)salts_updated;  // Keep variable used in log
        } else {
            // New contact from DHT — add it
            if (contacts_db_add(contacts[i], NULL) == 0) {
                added++;
                need_republish = true;  // Local changed, keep DHT in sync
                if (salts && salts[i]) {
                    contacts_db_set_salt(contacts[i], salts[i]);
                }
            } else {
                QGP_LOG_ERROR(LOG_TAG, "Failed to add contact '%s'\n", contacts[i]);
            }
        }
    }

    if (local_list) contacts_db_free_list(local_list);

    dht_contactlist_free_contacts(contacts, count);
    dht_contactlist_free_salts(salts, count);

    QGP_LOG_INFO(LOG_TAG, "DIFF sync complete: +%zu added, -%zu removed, %zu protected, %zu salt updates (DHT=%zu, local was %d)\n",
           added, removed, protected, salts_updated, count, local_count);

    // Phase 3: Republish contactlist if local state diverged from DHT.
    // This ensures the DHT contactlist stays in sync with local after adds/protections.
    if (need_republish) {
        QGP_LOG_WARN(LOG_TAG, "[CONTACTLIST_PUBLISH] DIFF sync: local diverged from DHT, republishing\n");
        messenger_sync_contacts_to_dht(ctx);
    }

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
    QGP_LOG_WARN(LOG_TAG, "[CONTACTLIST_PUBLISH] auto_sync: DHT fetch failed, publishing local contacts\n");
    return messenger_sync_contacts_to_dht(ctx);
}
