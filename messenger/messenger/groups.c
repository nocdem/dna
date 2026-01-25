/**
 * @file groups.c
 * @brief Group Management Implementation for GEK System
 *
 * Part of DNA Messenger - GEK System
 *
 * @date 2026-01-10
 */

#include "groups.h"
#include "gek.h"
#include "group_database.h"
#include "../crypto/utils/qgp_random.h"
#include "../crypto/utils/qgp_platform.h"
#include "../crypto/utils/qgp_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>

#define LOG_TAG "MSG_GROUPS"

/* ============================================================================
 * STATIC VARIABLES
 * ============================================================================ */

// Database handle (set during groups_init)
static sqlite3 *groups_db = NULL;

/* ============================================================================
 * HELPER FUNCTIONS
 * ============================================================================ */

/**
 * Generate UUID v4
 */
static int generate_uuid(char *uuid_out) {
    uint8_t random_bytes[16];
    if (qgp_randombytes(random_bytes, 16) != 0) {
        return -1;
    }

    // Set version (4) and variant bits
    random_bytes[6] = (random_bytes[6] & 0x0F) | 0x40;  // Version 4
    random_bytes[8] = (random_bytes[8] & 0x3F) | 0x80;  // Variant 1

    snprintf(uuid_out, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             random_bytes[0], random_bytes[1], random_bytes[2], random_bytes[3],
             random_bytes[4], random_bytes[5],
             random_bytes[6], random_bytes[7],
             random_bytes[8], random_bytes[9],
             random_bytes[10], random_bytes[11], random_bytes[12], random_bytes[13],
             random_bytes[14], random_bytes[15]);

    return 0;
}

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

    // Verify tables exist (created by group_database.c)
    const char *verify_sql = "SELECT 1 FROM groups LIMIT 1";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(groups_db, verify_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "groups table not found in groups.db\n");
        return -1;
    }
    sqlite3_finalize(stmt);

    QGP_LOG_INFO(LOG_TAG, "Initialized groups subsystem (using groups.db)\n");
    return 0;
}

/* ============================================================================
 * GROUP MANAGEMENT
 * ============================================================================ */

int groups_create(const char *name, const char *owner_fp, char *uuid_out) {
    if (!name || !owner_fp || !uuid_out) {
        QGP_LOG_ERROR(LOG_TAG, "groups_create: NULL parameter\n");
        return -1;
    }

    if (!groups_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    // Generate UUID
    char uuid[37];
    if (generate_uuid(uuid) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate UUID\n");
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);

    // Insert into groups table
    const char *sql = "INSERT INTO groups (uuid, name, created_at, is_owner, owner_fp) "
                      "VALUES (?, ?, ?, 1, ?)";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(groups_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare statement: %s\n", sqlite3_errmsg(groups_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, uuid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)now);
    sqlite3_bind_text(stmt, 4, owner_fp, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create group: %s\n", sqlite3_errmsg(groups_db));
        return -1;
    }

    // Add owner as first member
    const char *member_sql = "INSERT INTO group_members (group_uuid, fingerprint, added_at) "
                             "VALUES (?, ?, ?)";

    rc = sqlite3_prepare_v2(groups_db, member_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare member statement: %s\n", sqlite3_errmsg(groups_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, uuid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, owner_fp, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)now);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to add owner as member: %s\n", sqlite3_errmsg(groups_db));
        return -1;
    }

    // Generate initial GEK (v0)
    uint8_t initial_gek[GEK_KEY_SIZE];
    if (gek_generate(uuid, 0, initial_gek) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate initial GEK\n");
        return -1;
    }

    // Store GEK
    if (gek_store(uuid, 0, initial_gek) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to store initial GEK\n");
        return -1;
    }

    strncpy(uuid_out, uuid, 37);
    QGP_LOG_INFO(LOG_TAG, "Created group '%s' with UUID %s\n", name, uuid);
    return 0;
}

int groups_delete(const char *group_uuid, const char *my_fp) {
    if (!group_uuid || !my_fp) {
        return -1;
    }

    if (!groups_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    // Verify ownership
    if (groups_is_owner(group_uuid, my_fp) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "Only owner can delete group\n");
        return -1;
    }

    // Delete from all tables (cascade)
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

    // Delete GEKs
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

    // Delete group
    rc = sqlite3_prepare_v2(groups_db, sql_group, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        if (rc == SQLITE_DONE) {
            QGP_LOG_INFO(LOG_TAG, "Deleted group %s\n", group_uuid);
            return 0;
        }
    }

    QGP_LOG_ERROR(LOG_TAG, "Failed to delete group: %s\n", sqlite3_errmsg(groups_db));
    return -1;
}

int groups_leave(const char *group_uuid) {
    if (!group_uuid) {
        return -1;
    }

    if (!groups_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    // Delete from all tables (cascade) - no ownership check (anyone can leave)
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

    // Delete GEKs
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

    // Delete group
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

int groups_list(groups_info_t **groups_out, int *count_out) {
    if (!groups_out || !count_out) {
        return -1;
    }

    if (!groups_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    *groups_out = NULL;
    *count_out = 0;

    const char *sql = "SELECT uuid, name, created_at, is_owner, owner_fp FROM groups ORDER BY created_at DESC";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(groups_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare query: %s\n", sqlite3_errmsg(groups_db));
        return -1;
    }

    // Count results first
    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        count++;
    }
    sqlite3_reset(stmt);

    if (count == 0) {
        sqlite3_finalize(stmt);
        return 0;
    }

    // Allocate array
    groups_info_t *groups = (groups_info_t *)calloc(count, sizeof(groups_info_t));
    if (!groups) {
        sqlite3_finalize(stmt);
        return -1;
    }

    // Fetch results
    int idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < count) {
        const char *uuid = (const char *)sqlite3_column_text(stmt, 0);
        const char *name = (const char *)sqlite3_column_text(stmt, 1);
        uint64_t created = (uint64_t)sqlite3_column_int64(stmt, 2);
        int is_owner = sqlite3_column_int(stmt, 3);
        const char *owner_fp = (const char *)sqlite3_column_text(stmt, 4);

        if (uuid) strncpy(groups[idx].uuid, uuid, 36);
        if (name) strncpy(groups[idx].name, name, 127);
        groups[idx].created_at = created;
        groups[idx].is_owner = (is_owner != 0);
        if (owner_fp) strncpy(groups[idx].owner_fp, owner_fp, 128);
        idx++;
    }

    sqlite3_finalize(stmt);

    *groups_out = groups;
    *count_out = idx;
    return 0;
}

int groups_get_info(const char *group_uuid, groups_info_t *info_out) {
    if (!group_uuid || !info_out) {
        return -1;
    }

    if (!groups_db) {
        return -1;
    }

    const char *sql = "SELECT uuid, name, created_at, is_owner, owner_fp FROM groups WHERE uuid = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(groups_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const char *uuid = (const char *)sqlite3_column_text(stmt, 0);
        const char *name = (const char *)sqlite3_column_text(stmt, 1);
        uint64_t created = (uint64_t)sqlite3_column_int64(stmt, 2);
        int is_owner = sqlite3_column_int(stmt, 3);
        const char *owner_fp = (const char *)sqlite3_column_text(stmt, 4);

        memset(info_out, 0, sizeof(groups_info_t));
        if (uuid) strncpy(info_out->uuid, uuid, 36);
        if (name) strncpy(info_out->name, name, 127);
        info_out->created_at = created;
        info_out->is_owner = (is_owner != 0);
        if (owner_fp) strncpy(info_out->owner_fp, owner_fp, 128);

        sqlite3_finalize(stmt);
        return 0;
    }

    sqlite3_finalize(stmt);
    return -1;
}

void groups_free_list(groups_info_t *groups, int count) {
    (void)count;  // No internal allocations
    if (groups) {
        free(groups);
    }
}

/* ============================================================================
 * MEMBER MANAGEMENT
 * ============================================================================ */

int groups_get_members(const char *group_uuid, groups_member_t **members_out, int *count_out) {
    if (!group_uuid || !members_out || !count_out) {
        return -1;
    }

    if (!groups_db) {
        return -1;
    }

    *members_out = NULL;
    *count_out = 0;

    const char *sql = "SELECT fingerprint, added_at FROM group_members WHERE group_uuid = ? ORDER BY added_at";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(groups_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);

    // Count results first
    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        count++;
    }
    sqlite3_reset(stmt);

    if (count == 0) {
        sqlite3_finalize(stmt);
        return 0;
    }

    // Allocate array
    groups_member_t *members = (groups_member_t *)calloc(count, sizeof(groups_member_t));
    if (!members) {
        sqlite3_finalize(stmt);
        return -1;
    }

    // Fetch results
    int idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < count) {
        const char *fp = (const char *)sqlite3_column_text(stmt, 0);
        uint64_t added = (uint64_t)sqlite3_column_int64(stmt, 1);

        if (fp) strncpy(members[idx].fingerprint, fp, 128);
        members[idx].added_at = added;
        idx++;
    }

    sqlite3_finalize(stmt);

    *members_out = members;
    *count_out = idx;
    return 0;
}

int groups_add_member(const char *group_uuid, const char *member_fp, const char *my_fp) {
    if (!group_uuid || !member_fp || !my_fp) {
        return -1;
    }

    if (!groups_db) {
        return -1;
    }

    // Verify ownership
    if (groups_is_owner(group_uuid, my_fp) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "Only owner can add members\n");
        return -1;
    }

    // Check if already a member
    if (groups_is_member(group_uuid, member_fp) == 1) {
        QGP_LOG_INFO(LOG_TAG, "Already a member\n");
        return 0;  // Not an error
    }

    uint64_t now = (uint64_t)time(NULL);

    const char *sql = "INSERT INTO group_members (group_uuid, fingerprint, added_at) VALUES (?, ?, ?)";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(groups_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, member_fp, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)now);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to add member: %s\n", sqlite3_errmsg(groups_db));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Added member %.20s... to group %.8s...\n", member_fp, group_uuid);

    // Note: GEK rotation should be triggered by caller after DHT sync
    return 0;
}

int groups_remove_member(const char *group_uuid, const char *member_fp, const char *my_fp) {
    if (!group_uuid || !member_fp || !my_fp) {
        return -1;
    }

    if (!groups_db) {
        return -1;
    }

    // Verify ownership
    if (groups_is_owner(group_uuid, my_fp) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "Only owner can remove members\n");
        return -1;
    }

    // Can't remove owner
    groups_info_t info;
    if (groups_get_info(group_uuid, &info) == 0) {
        if (strcmp(info.owner_fp, member_fp) == 0) {
            QGP_LOG_ERROR(LOG_TAG, "Cannot remove owner from group\n");
            return -1;
        }
    }

    const char *sql = "DELETE FROM group_members WHERE group_uuid = ? AND fingerprint = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(groups_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, member_fp, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(groups_db);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE || changes == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to remove member\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Removed member %.20s... from group %.8s...\n", member_fp, group_uuid);

    // Note: GEK rotation should be triggered by caller after DHT sync
    return 0;
}

void groups_free_members(groups_member_t *members, int count) {
    (void)count;
    if (members) {
        free(members);
    }
}

/* ============================================================================
 * INVITATIONS
 * ============================================================================ */

int groups_save_invitation(const char *group_uuid, const char *group_name, const char *owner_fp) {
    if (!group_uuid || !group_name || !owner_fp) {
        return -1;
    }

    if (!groups_db) {
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);

    const char *sql = "INSERT OR REPLACE INTO pending_invitations "
                      "(group_uuid, group_name, owner_fp, received_at) VALUES (?, ?, ?, ?)";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(groups_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, group_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, owner_fp, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)now);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Saved invitation for group '%s'\n", group_name);
    return 0;
}

int groups_list_invitations(groups_invitation_t **invites_out, int *count_out) {
    if (!invites_out || !count_out) {
        return -1;
    }

    if (!groups_db) {
        return -1;
    }

    *invites_out = NULL;
    *count_out = 0;

    const char *sql = "SELECT group_uuid, group_name, owner_fp, received_at "
                      "FROM pending_invitations ORDER BY received_at DESC";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(groups_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    // Count results first
    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        count++;
    }
    sqlite3_reset(stmt);

    if (count == 0) {
        sqlite3_finalize(stmt);
        return 0;
    }

    // Allocate array
    groups_invitation_t *invites = (groups_invitation_t *)calloc(count, sizeof(groups_invitation_t));
    if (!invites) {
        sqlite3_finalize(stmt);
        return -1;
    }

    // Fetch results
    int idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && idx < count) {
        const char *uuid = (const char *)sqlite3_column_text(stmt, 0);
        const char *name = (const char *)sqlite3_column_text(stmt, 1);
        const char *owner = (const char *)sqlite3_column_text(stmt, 2);
        uint64_t received = (uint64_t)sqlite3_column_int64(stmt, 3);

        if (uuid) strncpy(invites[idx].group_uuid, uuid, 36);
        if (name) strncpy(invites[idx].group_name, name, 127);
        if (owner) strncpy(invites[idx].owner_fp, owner, 128);
        invites[idx].received_at = received;
        idx++;
    }

    sqlite3_finalize(stmt);

    *invites_out = invites;
    *count_out = idx;
    return 0;
}

int groups_accept_invitation(const char *group_uuid) {
    if (!group_uuid) {
        return -1;
    }

    if (!groups_db) {
        return -1;
    }

    // Get invitation info
    const char *sql = "SELECT group_name, owner_fp FROM pending_invitations WHERE group_uuid = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(groups_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);

    char group_name[128] = {0};
    char owner_fp[129] = {0};

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        QGP_LOG_ERROR(LOG_TAG, "Invitation not found\n");
        return -1;
    }

    const char *name = (const char *)sqlite3_column_text(stmt, 0);
    const char *owner = (const char *)sqlite3_column_text(stmt, 1);
    if (name) strncpy(group_name, name, 127);
    if (owner) strncpy(owner_fp, owner, 128);
    sqlite3_finalize(stmt);

    uint64_t now = (uint64_t)time(NULL);

    // Add to groups table (not owner)
    const char *insert_sql = "INSERT OR REPLACE INTO groups "
                             "(uuid, name, created_at, is_owner, owner_fp) VALUES (?, ?, ?, 0, ?)";

    rc = sqlite3_prepare_v2(groups_db, insert_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, group_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)now);
    sqlite3_bind_text(stmt, 4, owner_fp, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return -1;
    }

    // Remove from pending invitations
    const char *delete_sql = "DELETE FROM pending_invitations WHERE group_uuid = ?";

    rc = sqlite3_prepare_v2(groups_db, delete_sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    QGP_LOG_INFO(LOG_TAG, "Accepted invitation for group '%s'\n", group_name);
    return 0;
}

int groups_reject_invitation(const char *group_uuid) {
    if (!group_uuid) {
        return -1;
    }

    if (!groups_db) {
        return -1;
    }

    const char *sql = "DELETE FROM pending_invitations WHERE group_uuid = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(groups_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(groups_db);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_DONE && changes > 0) {
        QGP_LOG_INFO(LOG_TAG, "Rejected invitation for group %s\n", group_uuid);
        return 0;
    }

    return -1;
}

void groups_free_invitations(groups_invitation_t *invites, int count) {
    (void)count;
    if (invites) {
        free(invites);
    }
}

/* ============================================================================
 * MESSAGING
 * ============================================================================ */

int groups_save_message(const char *group_uuid, int message_id, const char *sender_fp,
                        uint64_t timestamp_ms, uint32_t gek_version, const char *plaintext) {
    if (!group_uuid || !sender_fp || !plaintext) {
        return -1;
    }

    if (!groups_db) {
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);

    const char *sql = "INSERT OR IGNORE INTO group_messages "
                      "(group_uuid, message_id, sender_fp, timestamp_ms, gek_version, plaintext, received_at) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?)";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(groups_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, message_id);
    sqlite3_bind_text(stmt, 3, sender_fp, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)timestamp_ms);
    sqlite3_bind_int(stmt, 5, (int)gek_version);
    sqlite3_bind_text(stmt, 6, plaintext, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 7, (sqlite3_int64)now);

    rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(groups_db);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return -1;
    }

    if (changes == 0) {
        // Duplicate message (already exists)
        return 1;
    }

    return 0;
}

int groups_is_member(const char *group_uuid, const char *my_fp) {
    if (!group_uuid || !my_fp) {
        return -1;
    }

    if (!groups_db) {
        return -1;
    }

    const char *sql = "SELECT 1 FROM group_members WHERE group_uuid = ? AND fingerprint = ?";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(groups_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, my_fp, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_ROW) ? 1 : 0;
}

int groups_is_owner(const char *group_uuid, const char *my_fp) {
    if (!group_uuid || !my_fp) {
        return -1;
    }

    if (!groups_db) {
        return -1;
    }

    const char *sql = "SELECT 1 FROM groups WHERE uuid = ? AND owner_fp = ? AND is_owner = 1";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(groups_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, my_fp, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_ROW) ? 1 : 0;
}

/* ============================================================================
 * BACKUP / RESTORE (Multi-Device Sync)
 * ============================================================================ */

int groups_export_all(groups_export_entry_t **entries_out, size_t *count_out) {
    if (!entries_out || !count_out) {
        QGP_LOG_ERROR(LOG_TAG, "groups_export_all: NULL parameter");
        return -1;
    }

    *entries_out = NULL;
    *count_out = 0;

    if (!groups_db) {
        // Not an error - groups module not used yet, return empty
        QGP_LOG_DEBUG(LOG_TAG, "groups_export_all: No groups database (not initialized)");
        return 0;
    }

    // Count groups
    const char *count_sql = "SELECT COUNT(*) FROM groups";
    sqlite3_stmt *count_stmt;
    if (sqlite3_prepare_v2(groups_db, count_sql, -1, &count_stmt, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare count statement: %s", sqlite3_errmsg(groups_db));
        return -1;
    }

    size_t total_count = 0;
    if (sqlite3_step(count_stmt) == SQLITE_ROW) {
        total_count = (size_t)sqlite3_column_int(count_stmt, 0);
    }
    sqlite3_finalize(count_stmt);

    if (total_count == 0) {
        QGP_LOG_INFO(LOG_TAG, "No groups to export");
        return 0;
    }

    // Allocate output array
    groups_export_entry_t *entries = calloc(total_count, sizeof(groups_export_entry_t));
    if (!entries) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate export entries");
        return -1;
    }

    // Query all groups
    const char *select_sql =
        "SELECT uuid, name, owner_fp, is_owner, created_at FROM groups";
    sqlite3_stmt *select_stmt;

    if (sqlite3_prepare_v2(groups_db, select_sql, -1, &select_stmt, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare select statement: %s", sqlite3_errmsg(groups_db));
        free(entries);
        return -1;
    }

    size_t idx = 0;
    while (sqlite3_step(select_stmt) == SQLITE_ROW && idx < total_count) {
        const char *uuid = (const char *)sqlite3_column_text(select_stmt, 0);
        const char *name = (const char *)sqlite3_column_text(select_stmt, 1);
        const char *owner_fp = (const char *)sqlite3_column_text(select_stmt, 2);
        int is_owner = sqlite3_column_int(select_stmt, 3);
        uint64_t created_at = (uint64_t)sqlite3_column_int64(select_stmt, 4);

        if (uuid) {
            strncpy(entries[idx].uuid, uuid, 36);
            entries[idx].uuid[36] = '\0';
        }
        if (name) {
            strncpy(entries[idx].name, name, 127);
            entries[idx].name[127] = '\0';
        }
        if (owner_fp) {
            strncpy(entries[idx].owner_fp, owner_fp, 128);
            entries[idx].owner_fp[128] = '\0';
        }
        entries[idx].is_owner = (is_owner != 0);
        entries[idx].created_at = created_at;
        entries[idx].members = NULL;
        entries[idx].member_count = 0;

        // Get members for this group
        const char *member_sql = "SELECT fingerprint FROM group_members WHERE group_uuid = ?";
        sqlite3_stmt *member_stmt;

        if (sqlite3_prepare_v2(groups_db, member_sql, -1, &member_stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(member_stmt, 1, uuid, -1, SQLITE_STATIC);

            // Count members first
            int member_count = 0;
            while (sqlite3_step(member_stmt) == SQLITE_ROW) {
                member_count++;
            }
            sqlite3_reset(member_stmt);

            if (member_count > 0) {
                entries[idx].members = calloc((size_t)member_count, sizeof(char *));
                if (entries[idx].members) {
                    int m_idx = 0;
                    while (sqlite3_step(member_stmt) == SQLITE_ROW && m_idx < member_count) {
                        const char *fp = (const char *)sqlite3_column_text(member_stmt, 0);
                        if (fp) {
                            entries[idx].members[m_idx] = strdup(fp);
                            if (!entries[idx].members[m_idx]) {
                                // strdup failed - cleanup previously allocated members
                                for (int j = 0; j < m_idx; j++) {
                                    free(entries[idx].members[j]);
                                }
                                free(entries[idx].members);
                                entries[idx].members = NULL;
                                entries[idx].member_count = 0;
                                break;  // Skip remaining members for this group
                            }
                            m_idx++;
                        }
                    }
                    if (entries[idx].members) {
                        entries[idx].member_count = m_idx;
                    }
                }
            }
            sqlite3_finalize(member_stmt);
        }

        idx++;
    }

    sqlite3_finalize(select_stmt);

    *entries_out = entries;
    *count_out = idx;

    QGP_LOG_INFO(LOG_TAG, "Exported %zu groups for backup", idx);
    return 0;
}

int groups_import_all(const groups_export_entry_t *entries, size_t count, int *imported_out) {
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

void groups_free_export_entries(groups_export_entry_t *entries, size_t count) {
    if (entries) {
        for (size_t i = 0; i < count; i++) {
            if (entries[i].members) {
                for (int m = 0; m < entries[i].member_count; m++) {
                    free(entries[i].members[m]);
                }
                free(entries[i].members);
            }
        }
        free(entries);
    }
}
