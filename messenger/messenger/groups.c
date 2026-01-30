/**
 * @file groups.c
 * @brief Group Management - Minimal Implementation
 *
 * This file was significantly cleaned up in v0.6.83 to remove dead code.
 * The original groups.c had functions that operated on the 'groups' table
 * in groups.db, but the application actually uses 'dht_group_cache' table
 * in messages.db (via dht_groups.c).
 *
 * Functions retained:
 * - groups_init(): Initialize database (required by messenger/init.c)
 * - groups_leave(): Clean up GEKs and messages when leaving a group
 * - groups_import_all(): Backward compatibility for old backup restores
 *
 * All other functions were removed as they were never called:
 * - groups_create, groups_delete, groups_list, groups_get_info, etc.
 * - These functions wrote to 'groups' table which was never read by the app
 * - The app uses dht_groups_* functions which operate on dht_group_cache
 *
 * Part of DNA Messenger - GEK System
 * @date 2026-01-30
 */

#include "groups.h"
#include "group_database.h"
#include "../crypto/utils/qgp_log.h"
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#define LOG_TAG "MSG_GROUPS"

/* ============================================================================
 * STATIC VARIABLES
 * ============================================================================ */

// Database handle (set during groups_init)
static sqlite3 *groups_db = NULL;

/* ============================================================================
 * INITIALIZATION
 * ============================================================================ */

int groups_init(void *unused_ctx) {
    (void)unused_ctx;  // Legacy parameter, no longer used

    // Get database handle from group_database singleton
    group_database_context_t *grp_db_ctx = group_database_get_instance();
    if (!grp_db_ctx) {
        QGP_LOG_ERROR(LOG_TAG, "group_database not initialized - call group_database_init() first\n");
        return -1;
    }

    groups_db = (sqlite3 *)group_database_get_db(grp_db_ctx);
    if (!groups_db) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get database handle from group_database\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Initialized groups subsystem (using groups.db)\n");
    return 0;
}

/* ============================================================================
 * GROUP CLEANUP (Leave Group)
 * ============================================================================ */

int groups_leave(const char *group_uuid) {
    if (!group_uuid) {
        return -1;
    }

    if (!groups_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    // Delete from all tables (cascade) - no ownership check (anyone can leave)
    // IMPORTANT: This cleans up GEKs (group_geks) and cached messages (group_messages)
    const char *sql_members = "DELETE FROM group_members WHERE group_uuid = ?";
    const char *sql_geks = "DELETE FROM group_geks WHERE group_uuid = ?";
    const char *sql_messages = "DELETE FROM group_messages WHERE group_uuid = ?";
    const char *sql_group = "DELETE FROM groups WHERE uuid = ?";

    sqlite3_stmt *stmt = NULL;
    int rc;

    // Delete members
    rc = sqlite3_prepare_v2(groups_db, sql_members, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    // Delete GEKs (important for security - removes encryption keys)
    rc = sqlite3_prepare_v2(groups_db, sql_geks, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    // Delete messages
    rc = sqlite3_prepare_v2(groups_db, sql_messages, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    // Delete group entry (if it exists in legacy table)
    rc = sqlite3_prepare_v2(groups_db, sql_group, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        if (rc == SQLITE_DONE) {
            QGP_LOG_INFO(LOG_TAG, "Left group %s (removed from local DB)\n", group_uuid);
            return 0;
        }
    }

    QGP_LOG_ERROR(LOG_TAG, "Failed to leave group: %s\n", sqlite3_errmsg(groups_db));
    return -1;
}

/* ============================================================================
 * BACKUP / RESTORE (Backward Compatibility)
 * ============================================================================ */

int groups_import_all(const groups_export_entry_t *entries, size_t count, int *imported_out) {
    /*
     * This function is kept for backward compatibility with old backups.
     * New backups (v0.6.83+) set group_count=0 since groups are synced via dht_grouplist.
     * Old backups may have group data which we import here.
     *
     * Note: This writes to the 'groups' table which is NOT read by the app
     * (the app uses dht_group_cache). But we keep it for data preservation.
     */
    if (!entries && count > 0) {
        QGP_LOG_ERROR(LOG_TAG, "groups_import_all: NULL entries with count > 0");
        return -1;
    }

    if (imported_out) {
        *imported_out = 0;
    }

    if (count == 0) {
        QGP_LOG_INFO(LOG_TAG, "No groups to import");
        return 0;
    }

    if (!groups_db) {
        QGP_LOG_ERROR(LOG_TAG, "groups_import_all: Database not initialized");
        return -1;
    }

    // Prepare group insert statement (INSERT OR IGNORE to skip duplicates)
    const char *insert_sql =
        "INSERT OR IGNORE INTO groups "
        "(uuid, name, owner_fp, is_owner, created_at) "
        "VALUES (?, ?, ?, ?, ?)";
    sqlite3_stmt *insert_stmt;

    if (sqlite3_prepare_v2(groups_db, insert_sql, -1, &insert_stmt, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare group insert statement: %s", sqlite3_errmsg(groups_db));
        return -1;
    }

    // Prepare member insert statement
    const char *member_sql =
        "INSERT OR IGNORE INTO group_members "
        "(group_uuid, fingerprint, added_at) "
        "VALUES (?, ?, ?)";
    sqlite3_stmt *member_stmt;

    if (sqlite3_prepare_v2(groups_db, member_sql, -1, &member_stmt, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare member insert statement: %s", sqlite3_errmsg(groups_db));
        sqlite3_finalize(insert_stmt);
        return -1;
    }

    int imported = 0;
    for (size_t i = 0; i < count; i++) {
        sqlite3_reset(insert_stmt);
        sqlite3_bind_text(insert_stmt, 1, entries[i].uuid, -1, SQLITE_STATIC);
        sqlite3_bind_text(insert_stmt, 2, entries[i].name, -1, SQLITE_STATIC);
        sqlite3_bind_text(insert_stmt, 3, entries[i].owner_fp, -1, SQLITE_STATIC);
        sqlite3_bind_int(insert_stmt, 4, entries[i].is_owner ? 1 : 0);
        sqlite3_bind_int64(insert_stmt, 5, (sqlite3_int64)entries[i].created_at);

        if (sqlite3_step(insert_stmt) == SQLITE_DONE) {
            if (sqlite3_changes(groups_db) > 0) {
                imported++;

                // Import members for this group
                for (int m = 0; m < entries[i].member_count; m++) {
                    if (entries[i].members && entries[i].members[m]) {
                        sqlite3_reset(member_stmt);
                        sqlite3_bind_text(member_stmt, 1, entries[i].uuid, -1, SQLITE_STATIC);
                        sqlite3_bind_text(member_stmt, 2, entries[i].members[m], -1, SQLITE_STATIC);
                        sqlite3_bind_int64(member_stmt, 3, (sqlite3_int64)entries[i].created_at);
                        sqlite3_step(member_stmt);
                    }
                }
            }
        } else {
            QGP_LOG_WARN(LOG_TAG, "Failed to import group %zu: %s", i, sqlite3_errmsg(groups_db));
        }
    }

    sqlite3_finalize(insert_stmt);
    sqlite3_finalize(member_stmt);

    if (imported_out) {
        *imported_out = imported;
    }

    QGP_LOG_INFO(LOG_TAG, "Imported %d/%zu groups from backup", imported, count);
    return 0;
}
