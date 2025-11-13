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
// NOTE: Group functions temporarily disabled - being migrated to DHT (Phase 3)
// See messenger_stubs.c for temporary stub implementations

#if 0  // DISABLED: PostgreSQL group functions (Phase 3 - DHT migration pending)

/**
 * Create a new group
 */
int messenger_create_group(
    messenger_context_t *ctx,
    const char *name,
    const char *description,
    const char **members,
    size_t member_count,
    int *group_id_out
) {
    if (!ctx || !name || !members || member_count == 0) {
        fprintf(stderr, "Error: Invalid arguments for group creation\n");
        return -1;
    }

    // Validate group name
    if (strlen(name) == 0) {
        fprintf(stderr, "Error: Group name cannot be empty\n");
        return -1;
    }

    // Begin transaction
    PGresult *res = PQexec(ctx->pg_conn, "BEGIN");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Begin transaction failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);

    // Insert group
    const char *insert_group_query =
        "INSERT INTO groups (name, description, creator) "
        "VALUES ($1, $2, $3) RETURNING id";

    const char *group_params[3] = {name, description ? description : "", ctx->identity};
    res = PQexecParams(ctx->pg_conn, insert_group_query, 3, NULL, group_params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Create group failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        PQexec(ctx->pg_conn, "ROLLBACK");
        return -1;
    }

    int group_id = atoi(PQgetvalue(res, 0, 0));
    PQclear(res);

    // Add creator as member with role 'creator'
    const char *add_creator_query =
        "INSERT INTO group_members (group_id, member, role) VALUES ($1, $2, 'creator')";

    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", group_id);
    const char *creator_params[2] = {group_id_str, ctx->identity};

    res = PQexecParams(ctx->pg_conn, add_creator_query, 2, NULL, creator_params, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Add creator to group failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        PQexec(ctx->pg_conn, "ROLLBACK");
        return -1;
    }
    PQclear(res);

    // Add other members with role 'member'
    const char *add_member_query =
        "INSERT INTO group_members (group_id, member, role) VALUES ($1, $2, 'member')";

    for (size_t i = 0; i < member_count; i++) {
        const char *member_params[2] = {group_id_str, members[i]};
        res = PQexecParams(ctx->pg_conn, add_member_query, 2, NULL, member_params, NULL, NULL, 0);

        if (PQresultStatus(res) != PGRES_COMMAND_OK) {
            fprintf(stderr, "Add member '%s' to group failed: %s\n",
                    members[i], PQerrorMessage(ctx->pg_conn));
            PQclear(res);
            PQexec(ctx->pg_conn, "ROLLBACK");
            return -1;
        }
        PQclear(res);
    }

    // Commit transaction
    res = PQexec(ctx->pg_conn, "COMMIT");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Commit transaction failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        PQexec(ctx->pg_conn, "ROLLBACK");
        return -1;
    }
    PQclear(res);

    if (group_id_out) {
        *group_id_out = group_id;
    }

    printf("✓ Group '%s' created with ID %d\n", name, group_id);
    printf("✓ Added %zu member(s) to group\n", member_count);
    return 0;
}

/**
 * Get list of all groups current user belongs to
 */
int messenger_get_groups(
    messenger_context_t *ctx,
    group_info_t **groups_out,
    int *count_out
) {
    if (!ctx || !groups_out || !count_out) {
        return -1;
    }

    const char *query =
        "SELECT g.id, g.name, g.description, g.creator, g.created_at, COUNT(gm.member) as member_count "
        "FROM groups g "
        "JOIN group_members gm ON g.id = gm.group_id "
        "WHERE g.id IN (SELECT group_id FROM group_members WHERE member = $1) "
        "GROUP BY g.id, g.name, g.description, g.creator, g.created_at "
        "ORDER BY g.created_at DESC";

    const char *params[1] = {ctx->identity};
    PGresult *res = PQexecParams(ctx->pg_conn, query, 1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Get groups failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    int rows = PQntuples(res);
    *count_out = rows;

    if (rows == 0) {
        *groups_out = NULL;
        PQclear(res);
        return 0;
    }

    // Allocate array
    group_info_t *groups = (group_info_t*)calloc(rows, sizeof(group_info_t));
    if (!groups) {
        fprintf(stderr, "Memory allocation failed\n");
        PQclear(res);
        return -1;
    }

    // Copy data
    for (int i = 0; i < rows; i++) {
        groups[i].id = atoi(PQgetvalue(res, i, 0));
        groups[i].name = strdup(PQgetvalue(res, i, 1));
        const char *desc = PQgetvalue(res, i, 2);
        groups[i].description = (desc && strlen(desc) > 0) ? strdup(desc) : NULL;
        groups[i].creator = strdup(PQgetvalue(res, i, 3));
        groups[i].created_at = strdup(PQgetvalue(res, i, 4));
        groups[i].member_count = atoi(PQgetvalue(res, i, 5));

        if (!groups[i].name || !groups[i].creator || !groups[i].created_at) {
            // Cleanup on error
            for (int j = 0; j <= i; j++) {
                free(groups[j].name);
                free(groups[j].description);
                free(groups[j].creator);
                free(groups[j].created_at);
            }
            free(groups);
            PQclear(res);
            return -1;
        }
    }

    *groups_out = groups;
    PQclear(res);
    return 0;
}

/**
 * Get group info by ID
 */
int messenger_get_group_info(
    messenger_context_t *ctx,
    int group_id,
    group_info_t *group_out
) {
    if (!ctx || !group_out) {
        return -1;
    }

    const char *query =
        "SELECT g.id, g.name, g.description, g.creator, g.created_at, COUNT(gm.member) as member_count "
        "FROM groups g "
        "JOIN group_members gm ON g.id = gm.group_id "
        "WHERE g.id = $1 "
        "GROUP BY g.id, g.name, g.description, g.creator, g.created_at";

    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", group_id);
    const char *params[1] = {group_id_str};

    PGresult *res = PQexecParams(ctx->pg_conn, query, 1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Get group info failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    if (PQntuples(res) == 0) {
        fprintf(stderr, "Group %d not found\n", group_id);
        PQclear(res);
        return -1;
    }

    group_out->id = atoi(PQgetvalue(res, 0, 0));
    group_out->name = strdup(PQgetvalue(res, 0, 1));
    const char *desc = PQgetvalue(res, 0, 2);
    group_out->description = (desc && strlen(desc) > 0) ? strdup(desc) : NULL;
    group_out->creator = strdup(PQgetvalue(res, 0, 3));
    group_out->created_at = strdup(PQgetvalue(res, 0, 4));
    group_out->member_count = atoi(PQgetvalue(res, 0, 5));

    PQclear(res);

    if (!group_out->name || !group_out->creator || !group_out->created_at) {
        free(group_out->name);
        free(group_out->description);
        free(group_out->creator);
        free(group_out->created_at);
        return -1;
    }

    return 0;
}

/**
 * Get members of a specific group
 */
int messenger_get_group_members(
    messenger_context_t *ctx,
    int group_id,
    char ***members_out,
    int *count_out
) {
    if (!ctx || !members_out || !count_out) {
        return -1;
    }

    const char *query =
        "SELECT member FROM group_members WHERE group_id = $1 ORDER BY joined_at ASC";

    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", group_id);
    const char *params[1] = {group_id_str};

    PGresult *res = PQexecParams(ctx->pg_conn, query, 1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Get group members failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    int rows = PQntuples(res);
    *count_out = rows;

    if (rows == 0) {
        *members_out = NULL;
        PQclear(res);
        return 0;
    }

    // Allocate array
    char **members = (char**)malloc(sizeof(char*) * rows);
    if (!members) {
        fprintf(stderr, "Memory allocation failed\n");
        PQclear(res);
        return -1;
    }

    // Copy member names
    for (int i = 0; i < rows; i++) {
        members[i] = strdup(PQgetvalue(res, i, 0));
        if (!members[i]) {
            // Cleanup on error
            for (int j = 0; j < i; j++) {
                free(members[j]);
            }
            free(members);
            PQclear(res);
            return -1;
        }
    }

    *members_out = members;
    PQclear(res);
    return 0;
}

/**
 * Add member to group
 */
int messenger_add_group_member(
    messenger_context_t *ctx,
    int group_id,
    const char *member
) {
    if (!ctx || !member) {
        return -1;
    }

    const char *query =
        "INSERT INTO group_members (group_id, member, role) VALUES ($1, $2, 'member')";

    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", group_id);
    const char *params[2] = {group_id_str, member};

    PGresult *res = PQexecParams(ctx->pg_conn, query, 2, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Add group member failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    PQclear(res);
    printf("✓ Added '%s' to group %d\n", member, group_id);
    return 0;
}

/**
 * Remove member from group
 */
int messenger_remove_group_member(
    messenger_context_t *ctx,
    int group_id,
    const char *member
) {
    if (!ctx || !member) {
        return -1;
    }

    const char *query =
        "DELETE FROM group_members WHERE group_id = $1 AND member = $2";

    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", group_id);
    const char *params[2] = {group_id_str, member};

    PGresult *res = PQexecParams(ctx->pg_conn, query, 2, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Remove group member failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    PQclear(res);
    printf("✓ Removed '%s' from group %d\n", member, group_id);
    return 0;
}

/**
 * Leave a group
 */
int messenger_leave_group(
    messenger_context_t *ctx,
    int group_id
) {
    if (!ctx) {
        return -1;
    }

    return messenger_remove_group_member(ctx, group_id, ctx->identity);
}

/**
 * Delete a group (creator only)
 */
int messenger_delete_group(
    messenger_context_t *ctx,
    int group_id
) {
    if (!ctx) {
        return -1;
    }

    // Verify current user is the creator
    const char *check_query = "SELECT creator FROM groups WHERE id = $1";

    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", group_id);
    const char *check_params[1] = {group_id_str};

    PGresult *res = PQexecParams(ctx->pg_conn, check_query, 1, NULL, check_params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Check group creator failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    if (PQntuples(res) == 0) {
        fprintf(stderr, "Group %d not found\n", group_id);
        PQclear(res);
        return -1;
    }

    const char *creator = PQgetvalue(res, 0, 0);
    if (strcmp(creator, ctx->identity) != 0) {
        fprintf(stderr, "Error: Only the group creator can delete the group\n");
        PQclear(res);
        return -1;
    }
    PQclear(res);

    // Delete group (CASCADE will delete members automatically)
    const char *delete_query = "DELETE FROM groups WHERE id = $1";
    const char *delete_params[1] = {group_id_str};

    res = PQexecParams(ctx->pg_conn, delete_query, 1, NULL, delete_params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Delete group failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    PQclear(res);
    printf("✓ Group %d deleted\n", group_id);
    return 0;
}

/**
 * Update group info (name, description)
 */
int messenger_update_group_info(
    messenger_context_t *ctx,
    int group_id,
    const char *name,
    const char *description
) {
    if (!ctx) {
        return -1;
    }

    if (!name && !description) {
        fprintf(stderr, "Error: Must provide at least name or description to update\n");
        return -1;
    }

    // Build dynamic query
    char query[512] = "UPDATE groups SET ";
    bool need_comma = false;

    if (name) {
        strcat(query, "name = $2");
        need_comma = true;
    }

    if (description) {
        if (need_comma) strcat(query, ", ");
        if (name) {
            strcat(query, "description = $3");
        } else {
            strcat(query, "description = $2");
        }
    }

    strcat(query, " WHERE id = $1");

    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", group_id);

    const char *params[3] = {group_id_str, NULL, NULL};
    int param_count = 1;

    if (name) {
        params[param_count++] = name;
    }
    if (description) {
        params[param_count++] = description;
    }

    PGresult *res = PQexecParams(ctx->pg_conn, query, param_count, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Update group info failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    PQclear(res);
    printf("✓ Group %d updated\n", group_id);
    return 0;
}

/**
 * Send message to group
 */
int messenger_send_group_message(
    messenger_context_t *ctx,
    int group_id,
    const char *message
) {
    if (!ctx || !message) {
        return -1;
    }

    // Get all group members except current user
    char **members = NULL;
    int member_count = 0;

    if (messenger_get_group_members(ctx, group_id, &members, &member_count) != 0) {
        fprintf(stderr, "Error: Failed to get group members\n");
        return -1;
    }

    if (member_count == 0) {
        fprintf(stderr, "Error: Group has no members\n");
        return -1;
    }

    // Filter out current user from recipients
    const char **recipients = (const char**)malloc(sizeof(char*) * member_count);
    size_t recipient_count = 0;

    for (int i = 0; i < member_count; i++) {
        if (strcmp(members[i], ctx->identity) != 0) {
            recipients[recipient_count++] = members[i];
        }
    }

    if (recipient_count == 0) {
        fprintf(stderr, "Error: No other members in group besides sender\n");
        free(recipients);
        for (int i = 0; i < member_count; i++) free(members[i]);
        free(members);
        return -1;
    }

    // Send message to all recipients
    int ret = messenger_send_message(ctx, recipients, recipient_count, message);

    // Cleanup
    free(recipients);
    for (int i = 0; i < member_count; i++) free(members[i]);
    free(members);

    if (ret == 0) {
        printf("✓ Message sent to group %d (%zu recipients)\n", group_id, recipient_count);
    }

    return ret;
}

/**
 * Get conversation for a group
 */
int messenger_get_group_conversation(
    messenger_context_t *ctx,
    int group_id,
    message_info_t **messages_out,
    int *count_out
) {
    if (!ctx || !messages_out || !count_out) {
        return -1;
    }

    const char *query =
        "SELECT id, sender, recipient, created_at, status, delivered_at, read_at "
        "FROM messages "
        "WHERE group_id = $1 "
        "ORDER BY created_at ASC";

    char group_id_str[32];
    snprintf(group_id_str, sizeof(group_id_str), "%d", group_id);
    const char *params[1] = {group_id_str};

    PGresult *res = PQexecParams(ctx->pg_conn, query, 1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Get group conversation failed: %s\n", PQerrorMessage(ctx->pg_conn));
        PQclear(res);
        return -1;
    }

    int rows = PQntuples(res);
    *count_out = rows;

    if (rows == 0) {
        *messages_out = NULL;
        PQclear(res);
        return 0;
    }

    // Allocate array
    message_info_t *messages = (message_info_t*)calloc(rows, sizeof(message_info_t));
    if (!messages) {
        fprintf(stderr, "Memory allocation failed\n");
        PQclear(res);
        return -1;
    }

    // Copy message data
    for (int i = 0; i < rows; i++) {
        messages[i].id = atoi(PQgetvalue(res, i, 0));
        messages[i].sender = strdup(PQgetvalue(res, i, 1));
        messages[i].recipient = strdup(PQgetvalue(res, i, 2));
        messages[i].timestamp = strdup(PQgetvalue(res, i, 3));
        const char *status = PQgetvalue(res, i, 4);
        messages[i].status = strdup(status ? status : "sent");
        const char *delivered_at = PQgetvalue(res, i, 5);
        messages[i].delivered_at = (delivered_at && strlen(delivered_at) > 0) ? strdup(delivered_at) : NULL;
        const char *read_at = PQgetvalue(res, i, 6);
        messages[i].read_at = (read_at && strlen(read_at) > 0) ? strdup(read_at) : NULL;
        messages[i].plaintext = NULL;

        if (!messages[i].sender || !messages[i].recipient || !messages[i].timestamp || !messages[i].status) {
            // Cleanup on error
            for (int j = 0; j <= i; j++) {
                free(messages[j].sender);
                free(messages[j].recipient);
                free(messages[j].timestamp);
                free(messages[j].status);
                free(messages[j].delivered_at);
                free(messages[j].read_at);
            }
            free(messages);
            PQclear(res);
            return -1;
        }
    }

    *messages_out = messages;
    PQclear(res);
    return 0;
}

/**
 * Free group array
 */
void messenger_free_groups(group_info_t *groups, int count) {
    if (!groups) {
        return;
    }

    for (int i = 0; i < count; i++) {
        free(groups[i].name);
        free(groups[i].description);
        free(groups[i].creator);
        free(groups[i].created_at);
    }
    free(groups);
}

#endif  // DISABLED: PostgreSQL group functions


// ============================================================================
// DHT CONTACT LIST SYNCHRONIZATION
// ============================================================================
// MODULARIZATION: Moved to messenger/contacts.{c,h}

/*
 * messenger_sync_contacts_to_dht() - MOVED to messenger/contacts.c
 * messenger_sync_contacts_from_dht() - MOVED to messenger/contacts.c
 * messenger_contacts_auto_sync() - MOVED to messenger/contacts.c
 */


