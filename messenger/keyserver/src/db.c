/*
 * Database Layer - PostgreSQL
 */

#include "db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

PGconn* db_connect(const config_t *config) {
    char conninfo[1024];
    snprintf(conninfo, sizeof(conninfo),
             "host=%s port=%d dbname=%s user=%s password=%s",
             config->db_host, config->db_port, config->db_name,
             config->db_user, config->db_password);

    PGconn *conn = PQconnectdb(conninfo);

    if (PQstatus(conn) != CONNECTION_OK) {
        LOG_ERROR("Database connection failed: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return NULL;
    }

    LOG_INFO("Connected to PostgreSQL: %s", config->db_name);
    return conn;
}

void db_disconnect(PGconn *conn) {
    if (conn) {
        PQfinish(conn);
    }
}

int db_insert_or_update_identity(PGconn *conn, const identity_t *identity) {
    const char *paramValues[9];
    char identity_str[MAX_IDENTITY_LENGTH + 1];

    // Build identity string
    snprintf(identity_str, sizeof(identity_str), "%s/%s",
             identity->handle, identity->device);

    // Check if identity exists and get current version
    const char *check_sql =
        "SELECT version FROM keyserver_identities WHERE identity = $1";
    const char *check_params[1] = {identity_str};

    PGresult *res = PQexecParams(conn, check_sql, 1, NULL, check_params,
                                 NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        LOG_ERROR("Version check failed: %s", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }

    int current_version = 0;
    if (PQntuples(res) > 0) {
        current_version = atoi(PQgetvalue(res, 0, 0));
    }
    PQclear(res);

    // Check version monotonicity
    if (current_version > 0 && identity->version <= current_version) {
        LOG_WARN("Version conflict: new=%d, current=%d",
                 identity->version, current_version);
        return -2;  // Version conflict
    }

    // Insert or update
    const char *sql =
        "INSERT INTO keyserver_identities "
        "(handle, device, identity, dilithium_pub, kyber_pub, inbox_key, "
        " version, updated_at, sig, schema_version) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 1) "
        "ON CONFLICT (identity) DO UPDATE SET "
        "dilithium_pub = $4, kyber_pub = $5, inbox_key = $6, "
        "version = $7, updated_at = $8, sig = $9, "
        "last_updated = NOW()";

    char version_str[32], updated_at_str[32];
    snprintf(version_str, sizeof(version_str), "%d", identity->version);
    snprintf(updated_at_str, sizeof(updated_at_str), "%d", identity->updated_at);

    paramValues[0] = identity->handle;
    paramValues[1] = identity->device;
    paramValues[2] = identity_str;
    paramValues[3] = identity->dilithium_pub;
    paramValues[4] = identity->kyber_pub;
    paramValues[5] = identity->inbox_key;
    paramValues[6] = version_str;
    paramValues[7] = updated_at_str;
    paramValues[8] = identity->sig;

    res = PQexecParams(conn, sql, 9, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        LOG_ERROR("Insert/update failed: %s", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }

    PQclear(res);
    LOG_INFO("Stored identity: %s (version %d)", identity_str, identity->version);
    return 0;
}

int db_lookup_identity(PGconn *conn, const char *identity_str, identity_t *identity) {
    const char *sql =
        "SELECT handle, device, identity, dilithium_pub, kyber_pub, inbox_key, "
        "version, updated_at, sig, schema_version, "
        "TO_CHAR(registered_at, 'YYYY-MM-DD HH24:MI:SS'), "
        "TO_CHAR(last_updated, 'YYYY-MM-DD HH24:MI:SS') "
        "FROM keyserver_identities WHERE identity = $1";

    const char *paramValues[1] = {identity_str};

    PGresult *res = PQexecParams(conn, sql, 1, NULL, paramValues,
                                 NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        LOG_ERROR("Lookup failed: %s", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }

    if (PQntuples(res) == 0) {
        PQclear(res);
        return -2;  // Not found
    }

    // Populate identity structure
    strncpy(identity->handle, PQgetvalue(res, 0, 0), MAX_HANDLE_LENGTH);
    strncpy(identity->device, PQgetvalue(res, 0, 1), MAX_HANDLE_LENGTH);
    strncpy(identity->identity, PQgetvalue(res, 0, 2), MAX_IDENTITY_LENGTH);
    identity->dilithium_pub = strdup(PQgetvalue(res, 0, 3));
    identity->kyber_pub = strdup(PQgetvalue(res, 0, 4));
    strncpy(identity->inbox_key, PQgetvalue(res, 0, 5), INBOX_KEY_HEX_LENGTH);
    identity->version = atoi(PQgetvalue(res, 0, 6));
    identity->updated_at = atoi(PQgetvalue(res, 0, 7));
    identity->sig = strdup(PQgetvalue(res, 0, 8));
    identity->schema_version = atoi(PQgetvalue(res, 0, 9));
    strncpy(identity->registered_at, PQgetvalue(res, 0, 10), 31);
    strncpy(identity->last_updated, PQgetvalue(res, 0, 11), 31);

    PQclear(res);
    return 0;
}

int db_list_identities(PGconn *conn, int limit, int offset, const char *search,
                       identity_t **identities, int *count) {
    char sql[1024];
    const char *paramValues[3];
    int param_count = 0;

    if (search && strlen(search) > 0) {
        snprintf(sql, sizeof(sql),
                 "SELECT handle, device, identity, version, "
                 "TO_CHAR(registered_at, 'YYYY-MM-DD HH24:MI:SS'), "
                 "TO_CHAR(last_updated, 'YYYY-MM-DD HH24:MI:SS') "
                 "FROM keyserver_identities "
                 "WHERE handle LIKE $1 "
                 "ORDER BY registered_at DESC LIMIT $2 OFFSET $3");

        char search_pattern[MAX_HANDLE_LENGTH + 2];
        snprintf(search_pattern, sizeof(search_pattern), "%s%%", search);
        paramValues[param_count++] = search_pattern;
    } else {
        snprintf(sql, sizeof(sql),
                 "SELECT handle, device, identity, version, "
                 "TO_CHAR(registered_at, 'YYYY-MM-DD HH24:MI:SS'), "
                 "TO_CHAR(last_updated, 'YYYY-MM-DD HH24:MI:SS') "
                 "FROM keyserver_identities "
                 "ORDER BY registered_at DESC LIMIT $1 OFFSET $2");
    }

    char limit_str[32], offset_str[32];
    snprintf(limit_str, sizeof(limit_str), "%d", limit);
    snprintf(offset_str, sizeof(offset_str), "%d", offset);

    if (search && strlen(search) > 0) {
        paramValues[param_count++] = limit_str;
        paramValues[param_count++] = offset_str;
    } else {
        paramValues[param_count++] = limit_str;
        paramValues[param_count++] = offset_str;
    }

    PGresult *res = PQexecParams(conn, sql, param_count, NULL, paramValues,
                                 NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        LOG_ERROR("List failed: %s", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }

    *count = PQntuples(res);
    *identities = calloc(*count, sizeof(identity_t));

    for (int i = 0; i < *count; i++) {
        identity_t *id = &(*identities)[i];
        strncpy(id->handle, PQgetvalue(res, i, 0), MAX_HANDLE_LENGTH);
        strncpy(id->device, PQgetvalue(res, i, 1), MAX_HANDLE_LENGTH);
        strncpy(id->identity, PQgetvalue(res, i, 2), MAX_IDENTITY_LENGTH);
        id->version = atoi(PQgetvalue(res, i, 3));
        strncpy(id->registered_at, PQgetvalue(res, i, 4), 31);
        strncpy(id->last_updated, PQgetvalue(res, i, 5), 31);
    }

    PQclear(res);
    return 0;
}

int db_count_identities(PGconn *conn) {
    const char *sql = "SELECT COUNT(*) FROM keyserver_identities";

    PGresult *res = PQexec(conn, sql);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        LOG_ERROR("Count failed: %s", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }

    int count = atoi(PQgetvalue(res, 0, 0));
    PQclear(res);

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
