/*
 * DNA Messenger - Group Invitations Database Implementation
 */

#include "group_invitations.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"

#define LOG_TAG "DB_GROUPS"

// Global database connection (per-identity)
static sqlite3 *g_invitations_db = NULL;
static char g_current_identity[256] = {0};

// Database schema
static const char *INVITATIONS_SCHEMA =
    "CREATE TABLE IF NOT EXISTS pending_invitations ("
    "    group_uuid TEXT PRIMARY KEY,"
    "    group_name TEXT NOT NULL,"
    "    inviter TEXT NOT NULL,"
    "    invited_at INTEGER NOT NULL,"
    "    status INTEGER DEFAULT 0,"  // 0=pending, 1=accepted, 2=rejected
    "    member_count INTEGER DEFAULT 0"
    ");";

/**
 * Initialize group invitations database
 */
int group_invitations_init(const char *identity) {
    QGP_LOG_WARN(LOG_TAG, ">>> INIT START identity=%s\n", identity ? identity : "(null)");

    if (!identity) {
        QGP_LOG_ERROR(LOG_TAG, "NULL identity\n");
        return -1;
    }

    // If already initialized for this identity, return success
    if (g_invitations_db && strcmp(g_current_identity, identity) == 0) {
        QGP_LOG_WARN(LOG_TAG, ">>> INIT: already initialized, returning 0\n");
        return 0;
    }

    // Close existing database if switching identity
    if (g_invitations_db) {
        group_invitations_cleanup();
    }

    // v0.3.0: Build database path: <data_dir>/db/invitations.db (flat structure)
    (void)identity;  // Unused in v0.3.0 flat structure
    char db_path[512];
    const char *data_dir = qgp_platform_app_data_dir();
    if (!data_dir) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get data directory\n");
        return -1;
    }
    snprintf(db_path, sizeof(db_path), "%s/db/invitations.db", data_dir);

    // Open database with FULLMUTEX for thread safety (DHT callbacks + main thread)
    int rc = sqlite3_open_v2(db_path, &g_invitations_db,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open database: %s\n",
                sqlite3_errmsg(g_invitations_db));
        sqlite3_close(g_invitations_db);
        g_invitations_db = NULL;
        return -1;
    }

    // Android force-close recovery: Set busy timeout and force WAL checkpoint
    sqlite3_busy_timeout(g_invitations_db, 5000);
    sqlite3_wal_checkpoint(g_invitations_db, NULL);

    // Create table
    char *err_msg = NULL;
    rc = sqlite3_exec(g_invitations_db, INVITATIONS_SCHEMA, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create table: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(g_invitations_db);
        g_invitations_db = NULL;
        return -1;
    }

    strncpy(g_current_identity, identity, sizeof(g_current_identity) - 1);
    QGP_LOG_WARN(LOG_TAG, ">>> INIT COMPLETE for identity: %s\n", identity);
    return 0;
}

/**
 * Store a new group invitation
 */
int group_invitations_store(const group_invitation_t *invitation) {
    if (!g_invitations_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!invitation) {
        QGP_LOG_ERROR(LOG_TAG, "NULL invitation\n");
        return -1;
    }

    // Check if invitation already exists
    sqlite3_stmt *check_stmt = NULL;
    const char *check_sql = "SELECT group_uuid FROM pending_invitations WHERE group_uuid = ?;";

    int rc = sqlite3_prepare_v2(g_invitations_db, check_sql, -1, &check_stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare check statement: %s\n",
                sqlite3_errmsg(g_invitations_db));
        return -1;
    }

    sqlite3_bind_text(check_stmt, 1, invitation->group_uuid, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(check_stmt);
    sqlite3_finalize(check_stmt);

    if (rc == SQLITE_ROW) {
        // Invitation already exists
        return -2;
    }

    // Insert new invitation
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT INTO pending_invitations "
                      "(group_uuid, group_name, inviter, invited_at, status, member_count) "
                      "VALUES (?, ?, ?, ?, ?, ?);";

    rc = sqlite3_prepare_v2(g_invitations_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare insert statement: %s\n",
                sqlite3_errmsg(g_invitations_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, invitation->group_uuid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, invitation->group_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, invitation->inviter, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, invitation->invited_at);
    sqlite3_bind_int(stmt, 5, invitation->status);
    sqlite3_bind_int(stmt, 6, invitation->member_count);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to insert invitation: %s\n",
                sqlite3_errmsg(g_invitations_db));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Stored invitation for group '%s' (UUID: %s)\n",
           invitation->group_name, invitation->group_uuid);
    return 0;
}

/**
 * Get all pending invitations
 */
int group_invitations_get_pending(group_invitation_t **invitations_out, int *count_out) {
    if (!g_invitations_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!invitations_out || !count_out) {
        QGP_LOG_ERROR(LOG_TAG, "NULL output parameters\n");
        return -1;
    }

    *invitations_out = NULL;
    *count_out = 0;

    // Query pending invitations
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT group_uuid, group_name, inviter, invited_at, status, member_count "
                      "FROM pending_invitations WHERE status = ? ORDER BY invited_at DESC;";

    int rc = sqlite3_prepare_v2(g_invitations_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare select statement: %s\n",
                sqlite3_errmsg(g_invitations_db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, INVITATION_STATUS_PENDING);

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

    // Allocate array (zero-initialized)
    group_invitation_t *invitations = calloc(count, sizeof(group_invitation_t));
    if (!invitations) {
        sqlite3_finalize(stmt);
        return -1;
    }

    // Fetch results
    int i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && i < count) {
        const char *uuid = (const char*)sqlite3_column_text(stmt, 0);
        const char *name = (const char*)sqlite3_column_text(stmt, 1);
        const char *inviter = (const char*)sqlite3_column_text(stmt, 2);
        int64_t invited_at = sqlite3_column_int64(stmt, 3);
        int status = sqlite3_column_int(stmt, 4);
        int member_count = sqlite3_column_int(stmt, 5);

        // Safe copy with NULL check and guaranteed null-termination
        if (uuid) {
            strncpy(invitations[i].group_uuid, uuid, sizeof(invitations[i].group_uuid) - 1);
        }
        invitations[i].group_uuid[sizeof(invitations[i].group_uuid) - 1] = '\0';

        if (name) {
            strncpy(invitations[i].group_name, name, sizeof(invitations[i].group_name) - 1);
        }
        invitations[i].group_name[sizeof(invitations[i].group_name) - 1] = '\0';

        if (inviter) {
            strncpy(invitations[i].inviter, inviter, sizeof(invitations[i].inviter) - 1);
        }
        invitations[i].inviter[sizeof(invitations[i].inviter) - 1] = '\0';

        invitations[i].invited_at = invited_at;
        invitations[i].status = (invitation_status_t)status;
        invitations[i].member_count = member_count;

        i++;
    }

    sqlite3_finalize(stmt);

    *invitations_out = invitations;
    *count_out = i;

    QGP_LOG_INFO(LOG_TAG, "Retrieved %d pending invitation(s)\n", i);
    return 0;
}

/**
 * Get a specific invitation by group UUID
 */
int group_invitations_get(const char *group_uuid, group_invitation_t **invitation_out) {
    if (!g_invitations_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!group_uuid || !invitation_out) {
        QGP_LOG_ERROR(LOG_TAG, "NULL parameters\n");
        return -1;
    }

    *invitation_out = NULL;

    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT group_uuid, group_name, inviter, invited_at, status, member_count "
                      "FROM pending_invitations WHERE group_uuid = ?;";

    int rc = sqlite3_prepare_v2(g_invitations_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare select statement: %s\n",
                sqlite3_errmsg(g_invitations_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -2;  // Not found
    }

    // Allocate invitation (zero-initialized to prevent garbage in padding/unused bytes)
    group_invitation_t *invitation = calloc(1, sizeof(group_invitation_t));
    if (!invitation) {
        sqlite3_finalize(stmt);
        return -1;
    }

    // Get column values (may be NULL)
    const char *uuid = (const char*)sqlite3_column_text(stmt, 0);
    const char *name = (const char*)sqlite3_column_text(stmt, 1);
    const char *inviter = (const char*)sqlite3_column_text(stmt, 2);
    int64_t invited_at = sqlite3_column_int64(stmt, 3);
    int status = sqlite3_column_int(stmt, 4);
    int member_count = sqlite3_column_int(stmt, 5);

    // Safe copy with guaranteed null-termination (calloc already zeroed the struct)
    if (uuid) {
        strncpy(invitation->group_uuid, uuid, sizeof(invitation->group_uuid) - 1);
    }
    invitation->group_uuid[sizeof(invitation->group_uuid) - 1] = '\0';

    if (name) {
        strncpy(invitation->group_name, name, sizeof(invitation->group_name) - 1);
    }
    invitation->group_name[sizeof(invitation->group_name) - 1] = '\0';

    if (inviter) {
        strncpy(invitation->inviter, inviter, sizeof(invitation->inviter) - 1);
    }
    invitation->inviter[sizeof(invitation->inviter) - 1] = '\0';

    invitation->invited_at = invited_at;
    invitation->status = (invitation_status_t)status;
    invitation->member_count = member_count;

    sqlite3_finalize(stmt);

    *invitation_out = invitation;
    return 0;
}

/**
 * Update invitation status
 */
int group_invitations_update_status(const char *group_uuid, invitation_status_t status) {
    if (!g_invitations_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!group_uuid) {
        QGP_LOG_ERROR(LOG_TAG, "NULL group_uuid\n");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;
    const char *sql = "UPDATE pending_invitations SET status = ? WHERE group_uuid = ?;";

    int rc = sqlite3_prepare_v2(g_invitations_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare update statement: %s\n",
                sqlite3_errmsg(g_invitations_db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, status);
    sqlite3_bind_text(stmt, 2, group_uuid, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to update invitation status: %s\n",
                sqlite3_errmsg(g_invitations_db));
        return -1;
    }

    const char *status_str = (status == INVITATION_STATUS_ACCEPTED) ? "accepted" :
                             (status == INVITATION_STATUS_REJECTED) ? "rejected" : "pending";
    QGP_LOG_INFO(LOG_TAG, "Updated invitation %s to status: %s\n", group_uuid, status_str);
    return 0;
}

/**
 * Delete an invitation
 */
int group_invitations_delete(const char *group_uuid) {
    if (!g_invitations_db) {
        QGP_LOG_ERROR(LOG_TAG, "Database not initialized\n");
        return -1;
    }

    if (!group_uuid) {
        QGP_LOG_ERROR(LOG_TAG, "NULL group_uuid\n");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;
    const char *sql = "DELETE FROM pending_invitations WHERE group_uuid = ?;";

    int rc = sqlite3_prepare_v2(g_invitations_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare delete statement: %s\n",
                sqlite3_errmsg(g_invitations_db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, group_uuid, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to delete invitation: %s\n",
                sqlite3_errmsg(g_invitations_db));
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Deleted invitation: %s\n", group_uuid);
    return 0;
}

/**
 * Free invitation array
 */
void group_invitations_free(group_invitation_t *invitations, int count) {
    (void)count;  // Unused parameter
    if (invitations) {
        free(invitations);
    }
}

/**
 * Cleanup invitations database
 */
void group_invitations_cleanup(void) {
    if (g_invitations_db) {
        sqlite3_close(g_invitations_db);
        g_invitations_db = NULL;
        g_current_identity[0] = '\0';
        QGP_LOG_INFO(LOG_TAG, "Cleanup complete\n");
    }
}
