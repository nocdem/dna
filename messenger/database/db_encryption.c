/**
 * Database Encryption — SQLCipher integration
 *
 * Key derivation from identity DSA secret key and encrypted
 * database open/create wrapper with legacy unencrypted DB handling.
 *
 * @file db_encryption.c
 * @date 2026-04-02
 */

#include "db_encryption.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/qgp_log.h"
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>

#define LOG_TAG "DB_ENCRYPT"

#define DB_KEY_DOMAIN_SEPARATOR "sqlcipher-db-key"

int db_derive_encryption_key(const uint8_t *secret_key, size_t sk_len,
                             char *hex_key_out, size_t hex_size)
{
    if (!secret_key || sk_len == 0 || !hex_key_out || hex_size < QGP_SHA3_512_HEX_LENGTH) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for key derivation");
        return -1;
    }

    /* Concatenate: secret_key || domain_separator */
    const char *separator = DB_KEY_DOMAIN_SEPARATOR;
    size_t sep_len = strlen(separator);
    size_t total_len = sk_len + sep_len;

    uint8_t *input = (uint8_t *)malloc(total_len);
    if (!input) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate memory for key derivation");
        return -1;
    }

    memcpy(input, secret_key, sk_len);
    memcpy(input + sk_len, separator, sep_len);

    /* SHA3-512 -> 128 hex chars + null */
    int rc = qgp_sha3_512_hex(input, total_len, hex_key_out, hex_size);

    /* Secure cleanup of temporary buffer */
    qgp_secure_memzero(input, total_len);
    free(input);

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "SHA3-512 hash failed");
        return -1;
    }

    return 0;
}

/**
 * Check if a file exists.
 */
static int file_exists(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0);
}

/**
 * Delete a database file and its WAL/SHM companions.
 */
static void delete_db_files(const char *path)
{
    char wal_path[1040];
    char shm_path[1040];
    snprintf(wal_path, sizeof(wal_path), "%s-wal", path);
    snprintf(shm_path, sizeof(shm_path), "%s-shm", path);

    remove(path);
    remove(wal_path);
    remove(shm_path);
}

int dna_db_open_encrypted(const char *path, const char *hex_key, sqlite3 **db_out)
{
    if (!path || !hex_key || !db_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for encrypted open");
        return -1;
    }

    *db_out = NULL;

    /* If file exists, check if it is already encrypted */
    if (file_exists(path)) {
        sqlite3 *test_db = NULL;
        int rc = sqlite3_open_v2(path, &test_db,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, NULL);
        if (rc != SQLITE_OK) {
            if (test_db) sqlite3_close(test_db);
            /* Cannot open at all — delete and recreate */
            QGP_LOG_WARN(LOG_TAG, "Cannot open %s (rc=%d), deleting and recreating", path, rc);
            delete_db_files(path);
            goto create_new;
        }

        /* Try to apply key and read */
        rc = sqlite3_key(test_db, hex_key, (int)strlen(hex_key));
        if (rc != SQLITE_OK) {
            QGP_LOG_WARN(LOG_TAG, "sqlite3_key failed for %s (rc=%d)", path, rc);
            sqlite3_close(test_db);
            delete_db_files(path);
            goto create_new;
        }

        rc = sqlite3_exec(test_db, "SELECT count(*) FROM sqlite_master;", NULL, NULL, NULL);
        if (rc == SQLITE_OK) {
            /* Already encrypted with correct key — use this handle */
            *db_out = test_db;
            return 0;
        }

        /* SQLITE_NOTADB = unencrypted legacy DB, or wrong key */
        QGP_LOG_WARN(LOG_TAG, "Legacy unencrypted DB detected: %s — deleting for fresh encrypted DB", path);
        sqlite3_close(test_db);
        delete_db_files(path);
    }

create_new:
    /* Create new encrypted database */
    {
        int rc = sqlite3_open_v2(path, db_out,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL);
        if (rc != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to create encrypted DB %s: %s (rc=%d)",
                path, *db_out ? sqlite3_errmsg(*db_out) : "NULL", rc);
            if (*db_out) {
                sqlite3_close(*db_out);
                *db_out = NULL;
            }
            return -1;
        }

        rc = sqlite3_key(*db_out, hex_key, (int)strlen(hex_key));
        if (rc != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG, "sqlite3_key failed for new DB %s (rc=%d)", path, rc);
            sqlite3_close(*db_out);
            *db_out = NULL;
            return -1;
        }

        /* Verify encryption works */
        rc = sqlite3_exec(*db_out, "SELECT count(*) FROM sqlite_master;", NULL, NULL, NULL);
        if (rc != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG, "Encrypted DB verification failed for %s: %s (rc=%d)",
                path, sqlite3_errmsg(*db_out), rc);
            sqlite3_close(*db_out);
            *db_out = NULL;
            return -1;
        }
    }

    QGP_LOG_INFO(LOG_TAG, "Encrypted database opened: %s", path);
    return 0;
}
