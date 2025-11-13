/*
 * DNA Messenger - PostgreSQL Implementation
 *
 * Phase 3: Local PostgreSQL (localhost)
 * Phase 4: Network PostgreSQL (remote server)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <stdbool.h>
#ifdef _WIN32
#include <windows.h>
#define popen _popen
#define pclose _pclose
// Windows doesn't have htonll/ntohll, define them
#define htonll(x) ((1==htonl(1)) ? (x) : (((uint64_t)htonl((x) & 0xFFFFFFFF)) << 32) | htonl((x) >> 32))
#define ntohll(x) htonll(x)
#else
#include <sys/time.h>
#include <unistd.h>  // For unlink(), close()
#include <dirent.h>  // For directory operations (migration detection)
#include <arpa/inet.h>  // For htonl, htonll
// Define htonll/ntohll if not available
#ifndef htonll
#define htonll(x) ((1==htonl(1)) ? (x) : (((uint64_t)htonl((x) & 0xFFFFFFFF)) << 32) | htonl((x) >> 32))
#define ntohll(x) htonll(x)
#endif
#endif
#include <json-c/json.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include "messenger.h"
#include "messenger_p2p.h"  // Phase 9.1b: P2P delivery integration
#include "dna_config.h"
#include "qgp_platform.h"
#include "qgp_dilithium.h"
#include "qgp_kyber.h"
#include "qgp_sha3.h"  // For SHA3-512 fingerprint computation
#include "dht/dht_singleton.h"  // Global DHT singleton
#include "dht/dht_identity_backup.h"  // DHT identity encrypted backup
#include "qgp_types.h"  // For qgp_key_load, qgp_key_free
#include "qgp.h"  // For cmd_gen_key_from_seed, cmd_export_pubkey
#include "bip39.h"  // For BIP39_MAX_MNEMONIC_LENGTH, bip39_validate_mnemonic, qgp_derive_seeds_from_mnemonic
#include "kyber_deterministic.h"  // For crypto_kem_keypair_derand
#include "qgp_aes.h"  // For qgp_aes256_encrypt
#include "aes_keywrap.h"  // For aes256_wrap_key
#include "qgp_random.h"  // For qgp_randombytes
#include "keyserver_cache.h"  // Phase 4: Keyserver cache
#include "dht/dht_keyserver.h"   // Phase 9.4: DHT-based keyserver
#include "dht/dht_context.h"     // Phase 9.4: DHT context management
#include "dht/dht_contactlist.h" // DHT contact list sync
#include "p2p/p2p_transport.h"   // For getting DHT context
#include "contacts_db.h"         // Phase 9.4: Local contacts database
#include "messenger/identity.h"  // Phase: Modularization - Identity utilities
#include "messenger/init.h"      // Phase: Modularization - Context management
#include "messenger/status.h"    // Phase: Modularization - Message status
#include "messenger/keys.h"      // Phase: Modularization - Public key management
#include "messenger/contacts.h"  // Phase: Modularization - DHT contact sync
#include "messenger/keygen.h"    // Phase: Modularization - Key generation
#include "messenger/messages.h"  // Phase: Modularization - Message operations

// Global configuration
static dna_config_t g_config;

// ============================================================================
// INITIALIZATION
// ============================================================================
// MODULARIZATION: Moved to messenger/init.{c,h}

/*
 * resolve_identity_to_fingerprint() - MOVED to messenger/init.c (static helper)
 * messenger_init() - MOVED to messenger/init.c
 * messenger_free() - MOVED to messenger/init.c
 * messenger_load_dht_identity() - MOVED to messenger/init.c
 */
// ============================================================================
// KEY GENERATION
// ============================================================================
// MODULARIZATION: Moved to messenger/keygen.{c,h}

/*
 * messenger_generate_keys() - MOVED to messenger/keygen.c
 * messenger_generate_keys_from_seeds() - MOVED to messenger/keygen.c
 * messenger_register_name() - MOVED to messenger/keygen.c
 * messenger_restore_keys() - MOVED to messenger/keygen.c
 * messenger_restore_keys_from_file() - MOVED to messenger/keygen.c
 */

// ============================================================================
// FINGERPRINT UTILITIES (Phase 4: Fingerprint-First Identity)
// ============================================================================
// MODULARIZATION: Moved to messenger/identity.{c,h}

/*
 * messenger_compute_identity_fingerprint() - MOVED to messenger/identity.c
 * messenger_is_fingerprint() - MOVED to messenger/identity.c
 * messenger_get_display_name() - MOVED to messenger/identity.c
 */

// ============================================================================
// IDENTITY MIGRATION (Phase 4: Old Names → Fingerprints)
// ============================================================================

/**
 * Detect old-style identity files that need migration
 */
int messenger_detect_old_identities(char ***identities_out, int *count_out) {
    if (!identities_out || !count_out) {
        fprintf(stderr, "ERROR: Invalid arguments to messenger_detect_old_identities\n");
        return -1;
    }

    const char *home = qgp_platform_home_dir();
    char dna_dir[512];
    snprintf(dna_dir, sizeof(dna_dir), "%s/.dna", home);

    // Scan for .dsa files
    char **identities = NULL;
    int count = 0;
    int capacity = 10;

    identities = malloc(capacity * sizeof(char*));
    if (!identities) {
        return -1;
    }

#ifdef _WIN32
    // Windows directory iteration
    char search_path[512];
    snprintf(search_path, sizeof(search_path), "%s\\*.dsa", dna_dir);

    WIN32_FIND_DATAA find_data;
    HANDLE handle = FindFirstFileA(search_path, &find_data);

    if (handle == INVALID_HANDLE_VALUE) {
        *identities_out = NULL;
        *count_out = 0;
        free(identities);
        return 0;  // No .dsa files found
    }

    do {
        const char *filename = find_data.cFileName;
        size_t len = strlen(filename);

        if (len < 5) continue;

        // Extract name (remove .dsa extension)
        char name[256];
        strncpy(name, filename, len - 4);
        name[len - 4] = '\0';
#else
    // POSIX directory iteration
    DIR *dir = opendir(dna_dir);
    if (!dir) {
        *identities_out = NULL;
        *count_out = 0;
        free(identities);
        return 0;  // No .dna directory, no identities to migrate
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // Look for .dsa files
        size_t len = strlen(entry->d_name);
        if (len < 5 || strcmp(entry->d_name + len - 4, ".dsa") != 0) {
            continue;
        }

        // Extract name (remove .dsa extension)
        char name[256];
        strncpy(name, entry->d_name, len - 4);
        name[len - 4] = '\0';
#endif

        // Skip if already a fingerprint (128 hex chars)
        if (messenger_is_fingerprint(name)) {
            continue;
        }

        // Skip backup directory
        if (strstr(name, "backup") != NULL) {
            continue;
        }

        // This is an old-style identity that needs migration
        if (count >= capacity) {
            capacity *= 2;
            char **new_identities = realloc(identities, capacity * sizeof(char*));
            if (!new_identities) {
                for (int i = 0; i < count; i++) free(identities[i]);
                free(identities);
#ifdef _WIN32
                FindClose(handle);
#else
                closedir(dir);
#endif
                return -1;
            }
            identities = new_identities;
        }

        identities[count] = strdup(name);
        if (!identities[count]) {
            for (int i = 0; i < count; i++) free(identities[i]);
            free(identities);
#ifdef _WIN32
            FindClose(handle);
#else
            closedir(dir);
#endif
            return -1;
        }
        count++;
#ifdef _WIN32
    } while (FindNextFileA(handle, &find_data));

    FindClose(handle);
#else
    }

    closedir(dir);
#endif

    *identities_out = identities;
    *count_out = count;
    return 0;
}

/**
 * Migrate identity files from old naming to fingerprint naming
 */
int messenger_migrate_identity_files(const char *old_name, char *fingerprint_out) {
    if (!old_name || !fingerprint_out) {
        fprintf(stderr, "ERROR: Invalid arguments to messenger_migrate_identity_files\n");
        return -1;
    }

    const char *home = qgp_platform_home_dir();
    char dna_dir[512];
    snprintf(dna_dir, sizeof(dna_dir), "%s/.dna", home);

    printf("[MIGRATION] Migrating identity '%s' to fingerprint-based naming...\n", old_name);

    // 1. Compute fingerprint from existing key file
    if (messenger_compute_identity_fingerprint(old_name, fingerprint_out) != 0) {
        fprintf(stderr, "[MIGRATION] Failed to compute fingerprint for '%s'\n", old_name);
        return -1;
    }

    printf("[MIGRATION] Computed fingerprint: %s\n", fingerprint_out);

    // 2. Create backup directory
    char backup_dir[512];
    snprintf(backup_dir, sizeof(backup_dir), "%s/backup_pre_migration", dna_dir);

    if (qgp_platform_mkdir(backup_dir) != 0) {
        // Directory might already exist, check if it's actually a directory
        if (!qgp_platform_is_directory(backup_dir)) {
            fprintf(stderr, "[MIGRATION] Failed to create backup directory\n");
            return -1;
        }
    }

    printf("[MIGRATION] Created backup directory: %s\n", backup_dir);

    // 3. Define file paths
    char old_dsa[512], old_kem[512], old_contacts[512];
    char new_dsa[512], new_kem[512], new_contacts[512];
    char backup_dsa[512], backup_kem[512], backup_contacts[512];

    snprintf(old_dsa, sizeof(old_dsa), "%s/%s.dsa", dna_dir, old_name);
    snprintf(old_kem, sizeof(old_kem), "%s/%s.kem", dna_dir, old_name);
    snprintf(old_contacts, sizeof(old_contacts), "%s/%s_contacts.db", dna_dir, old_name);

    snprintf(new_dsa, sizeof(new_dsa), "%s/%s.dsa", dna_dir, fingerprint_out);
    snprintf(new_kem, sizeof(new_kem), "%s/%s.kem", dna_dir, fingerprint_out);
    snprintf(new_contacts, sizeof(new_contacts), "%s/%s_contacts.db", dna_dir, fingerprint_out);

    snprintf(backup_dsa, sizeof(backup_dsa), "%s/%s.dsa", backup_dir, old_name);
    snprintf(backup_kem, sizeof(backup_kem), "%s/%s.kem", backup_dir, old_name);
    snprintf(backup_contacts, sizeof(backup_contacts), "%s/%s_contacts.db", backup_dir, old_name);

    // 4. Copy files to backup (before renaming)
    bool has_errors = false;

    if (file_exists(old_dsa)) {
        FILE *src = fopen(old_dsa, "rb");
        FILE *dst = fopen(backup_dsa, "wb");
        if (src && dst) {
            char buffer[8192];
            size_t bytes;
            while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
                fwrite(buffer, 1, bytes, dst);
            }
            fclose(src);
            fclose(dst);
            printf("[MIGRATION] Backed up: %s.dsa\n", old_name);
        } else {
            fprintf(stderr, "[MIGRATION] Warning: Failed to backup %s.dsa\n", old_name);
            if (src) fclose(src);
            if (dst) fclose(dst);
            has_errors = true;
        }
    }

    if (file_exists(old_kem)) {
        FILE *src = fopen(old_kem, "rb");
        FILE *dst = fopen(backup_kem, "wb");
        if (src && dst) {
            char buffer[8192];
            size_t bytes;
            while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
                fwrite(buffer, 1, bytes, dst);
            }
            fclose(src);
            fclose(dst);
            printf("[MIGRATION] Backed up: %s.kem\n", old_name);
        } else {
            fprintf(stderr, "[MIGRATION] Warning: Failed to backup %s.kem\n", old_name);
            if (src) fclose(src);
            if (dst) fclose(dst);
            has_errors = true;
        }
    }

    if (file_exists(old_contacts)) {
        FILE *src = fopen(old_contacts, "rb");
        FILE *dst = fopen(backup_contacts, "wb");
        if (src && dst) {
            char buffer[8192];
            size_t bytes;
            while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
                fwrite(buffer, 1, bytes, dst);
            }
            fclose(src);
            fclose(dst);
            printf("[MIGRATION] Backed up: %s_contacts.db\n", old_name);
        } else {
            if (src) fclose(src);
            if (dst) fclose(dst);
            // Contacts DB is optional, not an error if missing
        }
    }

    if (has_errors) {
        fprintf(stderr, "[MIGRATION] Backup had errors, aborting migration\n");
        return -1;
    }

    // 5. Rename files to use fingerprint
    if (file_exists(old_dsa)) {
        if (rename(old_dsa, new_dsa) != 0) {
            fprintf(stderr, "[MIGRATION] Failed to rename %s.dsa\n", old_name);
            return -1;
        }
        printf("[MIGRATION] Renamed: %s.dsa → %s.dsa\n", old_name, fingerprint_out);
    }

    if (file_exists(old_kem)) {
        if (rename(old_kem, new_kem) != 0) {
            fprintf(stderr, "[MIGRATION] Failed to rename %s.kem\n", old_name);
            // Try to rollback .dsa
            rename(new_dsa, old_dsa);
            return -1;
        }
        printf("[MIGRATION] Renamed: %s.kem → %s.kem\n", old_name, fingerprint_out);
    }

    if (file_exists(old_contacts)) {
        if (rename(old_contacts, new_contacts) != 0) {
            fprintf(stderr, "[MIGRATION] Warning: Failed to rename %s_contacts.db (non-fatal)\n", old_name);
            // Non-fatal, continue
        } else {
            printf("[MIGRATION] Renamed: %s_contacts.db → %s_contacts.db\n", old_name, fingerprint_out);
        }
    }

    printf("[MIGRATION] ✓ Migration complete for '%s'\n", old_name);
    printf("[MIGRATION] New fingerprint: %s\n", fingerprint_out);
    printf("[MIGRATION] Backups stored in: %s/\n", backup_dir);

    return 0;
}

/**
 * Check if an identity has already been migrated
 */
bool messenger_is_identity_migrated(const char *name) {
    if (!name) return false;

    // Compute fingerprint
    char fingerprint[129];
    if (messenger_compute_identity_fingerprint(name, fingerprint) != 0) {
        return false;
    }

    // Check if fingerprint-named files exist
    const char *home = qgp_platform_home_dir();
    char fingerprint_dsa[512];
    snprintf(fingerprint_dsa, sizeof(fingerprint_dsa), "%s/.dna/%s.dsa", home, fingerprint);

    return file_exists(fingerprint_dsa);
}

// ============================================================================
// PUBLIC KEY MANAGEMENT
// ============================================================================
// MODULARIZATION: Moved to messenger/keys.{c,h}

/*
 * base64_encode() - MOVED to messenger/keys.c (static helper)
 * base64_decode() - MOVED to messenger/keys.c (static helper)
 * messenger_store_pubkey() - MOVED to messenger/keys.c
 * messenger_load_pubkey() - MOVED to messenger/keys.c
 * messenger_list_pubkeys() - MOVED to messenger/keys.c
 * messenger_get_contact_list() - MOVED to messenger/keys.c
 */


// ============================================================================
// MESSAGE OPERATIONS
// ============================================================================
// MODULARIZATION: Moved to messenger/messages.{c,h}

/*
 * messenger_send_message() - MOVED to messenger/messages.c
 * messenger_list_messages() - MOVED to messenger/messages.c
 * messenger_list_sent_messages() - MOVED to messenger/messages.c
 * messenger_read_message() - MOVED to messenger/messages.c
 * messenger_decrypt_message() - MOVED to messenger/messages.c
 * messenger_delete_pubkey() - MOVED to messenger/messages.c
 * messenger_delete_message() - MOVED to messenger/messages.c
 * messenger_search_by_sender() - MOVED to messenger/messages.c
 * messenger_show_conversation() - MOVED to messenger/messages.c
 * messenger_get_conversation() - MOVED to messenger/messages.c
 * messenger_search_by_date() - MOVED to messenger/messages.c
 */

// ============================================================================
// GROUP MANAGEMENT
// ============================================================================
// MODULARIZATION: Legacy PostgreSQL functions removed (Phase 3)
// Active DHT-based group functions in messenger_stubs.c:
//   - messenger_create_group()
//   - messenger_add_group_member()
//   - messenger_remove_group_member()
//   - messenger_send_group_message()
//   - messenger_list_groups()
//   - messenger_get_group_members()
//   - messenger_delete_group()
//   - messenger_leave_group()
//   - messenger_update_group_info()
//   - messenger_list_group_messages()
//   - messenger_is_group_member()



// ============================================================================
// DHT CONTACT LIST SYNCHRONIZATION
// ============================================================================
// MODULARIZATION: Moved to messenger/contacts.{c,h}

/*
 * messenger_sync_contacts_to_dht() - MOVED to messenger/contacts.c
 * messenger_sync_contacts_from_dht() - MOVED to messenger/contacts.c
 * messenger_contacts_auto_sync() - MOVED to messenger/contacts.c
 */


