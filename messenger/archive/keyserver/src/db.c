/*
 * Database Layer - SQLite
 * Migrated from PostgreSQL (2025-11-03)
 */

#include "db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

sqlite3* db_connect(const config_t *config) {
    sqlite3 *db = NULL;

    // Use db_name as the SQLite file path
    int rc = sqlite3_open(config->db_name, &db);

    if (rc != SQLITE_OK) {
        LOG_ERROR("Cannot open SQLite database: %s", sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }

    // Enable foreign keys and WAL mode for better concurrency
    char *err_msg = NULL;
    sqlite3_exec(db, "PRAGMA foreign_keys = ON;", NULL, NULL, &err_msg);
    sqlite3_exec(db, "PRAGMA journal_mode = WAL;", NULL, NULL, &err_msg);
    sqlite3_exec(db, "PRAGMA synchronous = NORMAL;", NULL, NULL, &err_msg);

    LOG_INFO("Connected to SQLite database: %s", config->db_name);
    return db;
}

void db_disconnect(sqlite3 *conn) {
    if (conn) {
        sqlite3_close(conn);
    }
}

int db_insert_identity(sqlite3 *conn, const identity_t *identity) {
    sqlite3_stmt *stmt = NULL;
    int rc;

    // Check if identity already exists
    const char *check_sql = "SELECT 1 FROM keyserver_identities WHERE dna = ?";
    rc = sqlite3_prepare_v2(conn, check_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("Existence check prepare failed: %s", sqlite3_errmsg(conn));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, identity->dna, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);

    if (rc == SQLITE_ROW) {
        sqlite3_finalize(stmt);
        LOG_WARN("Identity already exists: %s", identity->dna);
        return -3;  // Already exists
    }
    sqlite3_finalize(stmt);

    // Insert new identity (version must be 1 for registration)
    const char *sql =
        "INSERT INTO keyserver_identities "
        "(dna, dilithium_pub, kyber_pub, cf20pub, "
        " version, updated_at, sig, schema_version) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 1)";

    rc = sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("Insert prepare failed: %s", sqlite3_errmsg(conn));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, identity->dna, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, identity->dilithium_pub, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, identity->kyber_pub, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, identity->cf20pub, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, identity->version);
    sqlite3_bind_int(stmt, 6, identity->updated_at);
    sqlite3_bind_text(stmt, 7, identity->sig, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("Insert failed: %s", sqlite3_errmsg(conn));
        return -1;
    }

    LOG_INFO("Registered identity: %s (version %d)", identity->dna, identity->version);
    return 0;
}

int db_update_identity(sqlite3 *conn, const identity_t *identity) {
    sqlite3_stmt *stmt = NULL;
    int rc;

    // Check if identity exists and get current version
    const char *check_sql = "SELECT version FROM keyserver_identities WHERE dna = ?";
    rc = sqlite3_prepare_v2(conn, check_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("Version check prepare failed: %s", sqlite3_errmsg(conn));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, identity->dna, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);

    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        LOG_WARN("Identity not found for update: %s", identity->dna);
        return -4;  // Not found
    }

    int current_version = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    // Check version monotonicity
    if (identity->version <= current_version) {
        LOG_WARN("Version conflict: new=%d, current=%d",
                 identity->version, current_version);
        return -2;  // Version conflict
    }

    // Update existing identity
    const char *sql =
        "UPDATE keyserver_identities SET "
        "dilithium_pub = ?, kyber_pub = ?, cf20pub = ?, "
        "version = ?, updated_at = ?, sig = ? "
        "WHERE dna = ?";

    rc = sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("Update prepare failed: %s", sqlite3_errmsg(conn));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, identity->dilithium_pub, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, identity->kyber_pub, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, identity->cf20pub, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, identity->version);
    sqlite3_bind_int(stmt, 5, identity->updated_at);
    sqlite3_bind_text(stmt, 6, identity->sig, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 7, identity->dna, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("Update failed: %s", sqlite3_errmsg(conn));
        return -1;
    }

    LOG_INFO("Updated identity: %s (version %d)", identity->dna, identity->version);
    return 0;
}

int db_insert_or_update_identity(sqlite3 *conn, const identity_t *identity) {
    sqlite3_stmt *stmt = NULL;
    int rc;

    // Check if identity exists and get current version
    const char *check_sql = "SELECT version FROM keyserver_identities WHERE dna = ?";
    rc = sqlite3_prepare_v2(conn, check_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("Version check prepare failed: %s", sqlite3_errmsg(conn));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, identity->dna, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);

    int current_version = 0;
    if (rc == SQLITE_ROW) {
        current_version = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);

    // Check version monotonicity
    if (current_version > 0 && identity->version <= current_version) {
        LOG_WARN("Version conflict: new=%d, current=%d",
                 identity->version, current_version);
        return -2;  // Version conflict
    }

    // Insert or update using SQLite's UPSERT (INSERT OR REPLACE)
    const char *sql =
        "INSERT INTO keyserver_identities "
        "(dna, dilithium_pub, kyber_pub, cf20pub, "
        " version, updated_at, sig, schema_version) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 1) "
        "ON CONFLICT(dna) DO UPDATE SET "
        "dilithium_pub = ?, kyber_pub = ?, cf20pub = ?, "
        "version = ?, updated_at = ?, sig = ?";

    rc = sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("Insert/update prepare failed: %s", sqlite3_errmsg(conn));
        return -1;
    }

    // Bind for INSERT
    sqlite3_bind_text(stmt, 1, identity->dna, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, identity->dilithium_pub, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, identity->kyber_pub, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, identity->cf20pub, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, identity->version);
    sqlite3_bind_int(stmt, 6, identity->updated_at);
    sqlite3_bind_text(stmt, 7, identity->sig, -1, SQLITE_STATIC);

    // Bind for UPDATE (same values)
    sqlite3_bind_text(stmt, 8, identity->dilithium_pub, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 9, identity->kyber_pub, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 10, identity->cf20pub, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 11, identity->version);
    sqlite3_bind_int(stmt, 12, identity->updated_at);
    sqlite3_bind_text(stmt, 13, identity->sig, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("Insert/update failed: %s", sqlite3_errmsg(conn));
        return -1;
    }

    LOG_INFO("Stored identity: %s (version %d)", identity->dna, identity->version);
    return 0;
}

int db_lookup_identity(sqlite3 *conn, const char *dna, identity_t *identity) {
    sqlite3_stmt *stmt = NULL;
    int rc;

    const char *sql =
        "SELECT dna, dilithium_pub, kyber_pub, cf20pub, "
        "version, updated_at, sig, schema_version, "
        "datetime(registered_at, 'unixepoch'), "
        "datetime(last_updated, 'unixepoch') "
        "FROM keyserver_identities WHERE dna = ?";

    rc = sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("Lookup prepare failed: %s", sqlite3_errmsg(conn));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, dna, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);

    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -2;  // Not found
    }

    // Populate identity structure
    strncpy(identity->dna, (const char*)sqlite3_column_text(stmt, 0), MAX_DNA_LENGTH);
    identity->dilithium_pub = strdup((const char*)sqlite3_column_text(stmt, 1));
    identity->kyber_pub = strdup((const char*)sqlite3_column_text(stmt, 2));
    strncpy(identity->cf20pub, (const char*)sqlite3_column_text(stmt, 3), CF20_ADDRESS_LENGTH);
    identity->version = sqlite3_column_int(stmt, 4);
    identity->updated_at = sqlite3_column_int(stmt, 5);
    identity->sig = strdup((const char*)sqlite3_column_text(stmt, 6));
    identity->schema_version = sqlite3_column_int(stmt, 7);

    // Format timestamps as strings
    const char *reg_at = (const char*)sqlite3_column_text(stmt, 8);
    const char *upd_at = (const char*)sqlite3_column_text(stmt, 9);
    strncpy(identity->registered_at, reg_at ? reg_at : "", 31);
    strncpy(identity->last_updated, upd_at ? upd_at : "", 31);

    sqlite3_finalize(stmt);
    return 0;
}

int db_list_identities(sqlite3 *conn, int limit, int offset, const char *search,
                       identity_t **identities, int *count) {
    sqlite3_stmt *stmt = NULL;
    int rc;
    char sql[1024];

    if (search && strlen(search) > 0) {
        snprintf(sql, sizeof(sql),
                 "SELECT dna, version, "
                 "datetime(registered_at, 'unixepoch'), "
                 "datetime(last_updated, 'unixepoch') "
                 "FROM keyserver_identities "
                 "WHERE dna LIKE ? || '%%' "
                 "ORDER BY registered_at DESC LIMIT ? OFFSET ?");
    } else {
        snprintf(sql, sizeof(sql),
                 "SELECT dna, version, "
                 "datetime(registered_at, 'unixepoch'), "
                 "datetime(last_updated, 'unixepoch') "
                 "FROM keyserver_identities "
                 "ORDER BY registered_at DESC LIMIT ? OFFSET ?");
    }

    rc = sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("List prepare failed: %s", sqlite3_errmsg(conn));
        return -1;
    }

    int param_idx = 1;
    if (search && strlen(search) > 0) {
        sqlite3_bind_text(stmt, param_idx++, search, -1, SQLITE_STATIC);
    }
    sqlite3_bind_int(stmt, param_idx++, limit);
    sqlite3_bind_int(stmt, param_idx++, offset);

    // Count results
    int result_count = 0;
    identity_t *temp_identities = calloc(limit, sizeof(identity_t));

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        identity_t *id = &temp_identities[result_count];
        strncpy(id->dna, (const char*)sqlite3_column_text(stmt, 0), MAX_DNA_LENGTH);
        id->version = sqlite3_column_int(stmt, 1);

        const char *reg_at = (const char*)sqlite3_column_text(stmt, 2);
        const char *upd_at = (const char*)sqlite3_column_text(stmt, 3);
        strncpy(id->registered_at, reg_at ? reg_at : "", 31);
        strncpy(id->last_updated, upd_at ? upd_at : "", 31);

        result_count++;
    }

    sqlite3_finalize(stmt);

    *count = result_count;
    *identities = temp_identities;

    return 0;
}

int db_count_identities(sqlite3 *conn) {
    sqlite3_stmt *stmt = NULL;
    int rc;

    const char *sql = "SELECT COUNT(*) FROM keyserver_identities";

    rc = sqlite3_prepare_v2(conn, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        LOG_ERROR("Count prepare failed: %s", sqlite3_errmsg(conn));
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        LOG_ERROR("Count failed: %s", sqlite3_errmsg(conn));
        return -1;
    }

    int count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    return count;
}

void db_free_identity(identity_t *identity) {
    if (identity) {
        if (identity->dilithium_pub) free(identity->dilithium_pub);
        if (identity->kyber_pub) free(identity->kyber_pub);
        if (identity->sig) free(identity->sig);
    }
}

void db_free_identities(identity_t *identities, int count) {
    if (identities) {
        for (int i = 0; i < count; i++) {
            db_free_identity(&identities[i]);
        }
        free(identities);
    }
}
