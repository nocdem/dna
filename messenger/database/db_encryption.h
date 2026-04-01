/**
 * Database Encryption — SQLCipher integration
 *
 * Provides key derivation from identity DSA secret key and
 * encrypted database open/create wrapper.
 *
 * @file db_encryption.h
 * @date 2026-04-02
 */

#ifndef DB_ENCRYPTION_H
#define DB_ENCRYPTION_H

#include <sqlite3.h>
#include <stdint.h>
#include <stddef.h>

/* SQLCipher encryption key function.
 * Some platform headers omit this declaration — provide fallback. */
int sqlite3_key(sqlite3 *db, const void *pKey, int nKey);

/**
 * Derive database encryption key from DSA secret key.
 *
 * Computes: SHA3-512(secret_key || "sqlcipher-db-key") → 128-char hex string
 *
 * @param secret_key    DSA secret key bytes (4896 bytes for Dilithium5)
 * @param sk_len        Length of secret key
 * @param hex_key_out   Output buffer for hex string (must be >= 129 bytes)
 * @param hex_size      Size of output buffer
 * @return 0 on success, -1 on error
 */
int db_derive_encryption_key(const uint8_t *secret_key, size_t sk_len,
                             char *hex_key_out, size_t hex_size);

/**
 * Open an encrypted database.
 *
 * If the file exists and is unencrypted (legacy), it is deleted along with
 * any WAL/SHM files, and a new encrypted database is created.
 * If the file exists and is already encrypted, it is opened normally.
 * If the file does not exist, a new encrypted database is created.
 *
 * Only performs open + sqlite3_key. Does NOT set busy_timeout, WAL mode,
 * or any other pragmas — each module handles its own setup.
 *
 * @param path      Path to the database file
 * @param hex_key   128-char hex encryption key (from db_derive_encryption_key)
 * @param db_out    Output: opened sqlite3 handle
 * @return 0 on success, -1 on error
 */
int dna_db_open_encrypted(const char *path, const char *hex_key, sqlite3 **db_out);

#endif /* DB_ENCRYPTION_H */
