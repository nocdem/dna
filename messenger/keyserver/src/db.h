/*
 * Database Layer - SQLite
 * Migrated from PostgreSQL (2025-11-03)
 */

#ifndef DB_H
#define DB_H

#include "keyserver.h"
#include <sqlite3.h>

/**
 * Connect to SQLite database
 *
 * @param config: Configuration with DB file path
 * @return Database connection or NULL on error
 */
sqlite3* db_connect(const config_t *config);

/**
 * Disconnect from database
 *
 * @param conn: Database connection
 */
void db_disconnect(sqlite3 *conn);

/**
 * Insert new identity (registration only)
 *
 * @param conn: Database connection
 * @param identity: Identity data to insert
 * @return 0 on success, -1 on error, -3 if already exists
 */
int db_insert_identity(sqlite3 *conn, const identity_t *identity);

/**
 * Update existing identity (update only)
 *
 * @param conn: Database connection
 * @param identity: Identity data to update
 * @return 0 on success, -1 on error, -2 on version conflict, -4 if not found
 */
int db_update_identity(sqlite3 *conn, const identity_t *identity);

/**
 * Insert or update identity in keyserver (DEPRECATED - use insert or update)
 *
 * @param conn: Database connection
 * @param identity: Identity data to insert/update
 * @return 0 on success, -1 on error, -2 on version conflict
 */
int db_insert_or_update_identity(sqlite3 *conn, const identity_t *identity);

/**
 * Lookup identity by DNA handle
 *
 * @param conn: Database connection
 * @param dna: DNA handle string
 * @param identity: Identity structure to populate
 * @return 0 on success, -1 on error, -2 if not found
 */
int db_lookup_identity(sqlite3 *conn, const char *dna, identity_t *identity);

/**
 * List all identities with pagination
 *
 * @param conn: Database connection
 * @param limit: Maximum number of results
 * @param offset: Offset for pagination
 * @param search: Optional search prefix (NULL for all)
 * @param identities: Array to populate with results
 * @param count: Number of results returned
 * @return 0 on success, -1 on error
 */
int db_list_identities(sqlite3 *conn, int limit, int offset, const char *search,
                       identity_t **identities, int *count);

/**
 * Get total count of identities
 *
 * @param conn: Database connection
 * @return Count or -1 on error
 */
int db_count_identities(sqlite3 *conn);

/**
 * Free identity structure
 *
 * @param identity: Identity to free
 */
void db_free_identity(identity_t *identity);

/**
 * Free array of identities
 *
 * @param identities: Array of identities
 * @param count: Number of identities
 */
void db_free_identities(identity_t *identities, int count);

#endif // DB_H
