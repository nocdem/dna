/**
 * @file zone.c
 * @brief DNAC Zone Manager Implementation (v0.10.0)
 *
 * Manages multiple independent blockchain zones within a single
 * witness process. Each zone has its own BFT context, UTXO set,
 * ledger, block storage, and SQLite database.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/zone.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <dirent.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "ZONE"

/* External subsystem init functions (from nullifier.c, ledger.c, utxo_set.c, block.c) */
extern int witness_nullifier_init_db(sqlite3 *db);
extern int witness_ledger_init_with_db(sqlite3 *db);
extern int witness_utxo_set_init_with_db(sqlite3 *db);
extern int witness_block_init_with_db(sqlite3 *db);

/* ============================================================================
 * Zone Manager Lifecycle
 * ========================================================================== */

dnac_zone_manager_t *dnac_zone_manager_create(void) {
    dnac_zone_manager_t *mgr = calloc(1, sizeof(dnac_zone_manager_t));
    if (!mgr) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate zone manager");
        return NULL;
    }

    pthread_mutex_init(&mgr->mutex, NULL);
    mgr->zone_count = 0;

    QGP_LOG_INFO(LOG_TAG, "Zone manager created (max %d zones)", DNAC_MAX_ZONES);
    return mgr;
}

void dnac_zone_manager_destroy(dnac_zone_manager_t *mgr) {
    if (!mgr) return;

    pthread_mutex_lock(&mgr->mutex);
    for (int i = 0; i < mgr->zone_count; i++) {
        dnac_zone_shutdown(&mgr->zones[i]);
    }
    mgr->zone_count = 0;
    pthread_mutex_unlock(&mgr->mutex);

    if (mgr->privkey) {
        memset(mgr->privkey, 0, mgr->privkey_size);
        free(mgr->privkey);
        mgr->privkey = NULL;
    }

    pthread_mutex_destroy(&mgr->mutex);
    free(mgr);
    QGP_LOG_INFO(LOG_TAG, "Zone manager destroyed");
}

/* ============================================================================
 * Zone Lookup
 * ========================================================================== */

dnac_zone_t *dnac_zone_lookup(dnac_zone_manager_t *mgr, const uint8_t *chain_id) {
    if (!mgr || !chain_id) return NULL;

    pthread_mutex_lock(&mgr->mutex);
    for (int i = 0; i < mgr->zone_count; i++) {
        if (!mgr->zones[i].active) continue;
        if (memcmp(mgr->zones[i].chain_id, chain_id, DNAC_CHAIN_ID_SIZE) == 0) {
            pthread_mutex_unlock(&mgr->mutex);
            return &mgr->zones[i];
        }
    }

    /* Also match pre-genesis zones (all-zeros chain_id) against all-zeros lookup */
    if (dnac_chain_id_is_zero(chain_id)) {
        for (int i = 0; i < mgr->zone_count; i++) {
            if (mgr->zones[i].active && dnac_chain_id_is_zero(mgr->zones[i].chain_id)) {
                pthread_mutex_unlock(&mgr->mutex);
                return &mgr->zones[i];
            }
        }
    }

    pthread_mutex_unlock(&mgr->mutex);
    return NULL;
}

/* ============================================================================
 * Zone Creation
 * ========================================================================== */

dnac_zone_t *dnac_zone_create(dnac_zone_manager_t *mgr, const char *name,
                               const uint8_t *chain_id) {
    if (!mgr || !name) return NULL;

    pthread_mutex_lock(&mgr->mutex);

    if (mgr->zone_count >= DNAC_MAX_ZONES) {
        QGP_LOG_ERROR(LOG_TAG, "Maximum zones reached (%d)", DNAC_MAX_ZONES);
        pthread_mutex_unlock(&mgr->mutex);
        return NULL;
    }

    dnac_zone_t *zone = &mgr->zones[mgr->zone_count];
    memset(zone, 0, sizeof(*zone));

    zone->active = true;
    zone->block_height = UINT64_MAX;  /* No blocks yet */
    strncpy(zone->zone_name, name, DNAC_ZONE_NAME_SIZE - 1);

    if (chain_id) {
        memcpy(zone->chain_id, chain_id, DNAC_CHAIN_ID_SIZE);
    }

    mgr->zone_count++;

    char hex[17];
    dnac_chain_id_short_hex(zone->chain_id, hex);
    QGP_LOG_INFO(LOG_TAG, "Zone '%s' created (chain_id=%s, index=%d)",
                 name, dnac_chain_id_is_zero(zone->chain_id) ? "pre-genesis" : hex,
                 mgr->zone_count - 1);

    pthread_mutex_unlock(&mgr->mutex);
    return zone;
}

dnac_zone_t *dnac_zone_get_default(dnac_zone_manager_t *mgr) {
    if (!mgr || mgr->zone_count == 0) return NULL;
    return &mgr->zones[0];
}

/* ============================================================================
 * Zone Database
 * ========================================================================== */

/**
 * Full schema for a zone database — same as nullifier.c schema
 * but self-contained so each zone DB is independent.
 */
static const char *zone_schema =
    "CREATE TABLE IF NOT EXISTS nullifiers ("
    "  nullifier BLOB PRIMARY KEY,"
    "  tx_hash BLOB NOT NULL,"
    "  timestamp INTEGER NOT NULL,"
    "  replicated INTEGER DEFAULT 0"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_nullifiers_replicated ON nullifiers(replicated);"

    "CREATE TABLE IF NOT EXISTS genesis_state ("
    "  id INTEGER PRIMARY KEY CHECK (id = 1),"
    "  genesis_hash BLOB NOT NULL,"
    "  total_supply INTEGER NOT NULL,"
    "  genesis_timestamp INTEGER NOT NULL,"
    "  genesis_commitment BLOB NOT NULL"
    ");"

    "CREATE TABLE IF NOT EXISTS ledger_entries ("
    "  sequence_number INTEGER PRIMARY KEY,"
    "  tx_hash BLOB UNIQUE NOT NULL,"
    "  tx_type INTEGER NOT NULL,"
    "  nullifiers BLOB,"
    "  output_commitment BLOB,"
    "  merkle_root BLOB NOT NULL,"
    "  timestamp INTEGER NOT NULL,"
    "  epoch INTEGER NOT NULL"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_ledger_tx_hash ON ledger_entries(tx_hash);"
    "CREATE INDEX IF NOT EXISTS idx_ledger_epoch ON ledger_entries(epoch);"

    "CREATE TABLE IF NOT EXISTS supply_tracking ("
    "  id INTEGER PRIMARY KEY CHECK (id = 1),"
    "  genesis_supply INTEGER NOT NULL,"
    "  total_burned INTEGER NOT NULL DEFAULT 0,"
    "  current_supply INTEGER NOT NULL,"
    "  last_tx_hash BLOB NOT NULL,"
    "  last_sequence INTEGER NOT NULL"
    ");"

    "CREATE TABLE IF NOT EXISTS utxo_commitments ("
    "  commitment BLOB PRIMARY KEY,"
    "  tx_hash BLOB NOT NULL,"
    "  output_index INTEGER NOT NULL,"
    "  amount INTEGER NOT NULL,"
    "  owner_commit BLOB NOT NULL,"
    "  created_epoch INTEGER NOT NULL,"
    "  spent_epoch INTEGER,"
    "  UNIQUE(tx_hash, output_index)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_utxo_owner ON utxo_commitments(owner_commit);"
    "CREATE INDEX IF NOT EXISTS idx_utxo_unspent ON utxo_commitments(spent_epoch) WHERE spent_epoch IS NULL;"

    "CREATE TABLE IF NOT EXISTS epoch_roots ("
    "  epoch INTEGER PRIMARY KEY,"
    "  first_sequence INTEGER,"
    "  last_sequence INTEGER,"
    "  utxo_root BLOB NOT NULL,"
    "  ledger_root BLOB NOT NULL,"
    "  utxo_count INTEGER NOT NULL,"
    "  total_supply INTEGER NOT NULL,"
    "  timestamp INTEGER NOT NULL"
    ");"

    "CREATE TABLE IF NOT EXISTS ledger_checkpoints ("
    "  checkpoint_seq INTEGER PRIMARY KEY,"
    "  merkle_root BLOB NOT NULL"
    ");"

    "CREATE TABLE IF NOT EXISTS utxo_set ("
    "  nullifier BLOB(64) PRIMARY KEY,"
    "  owner_fingerprint TEXT NOT NULL,"
    "  amount INTEGER NOT NULL,"
    "  tx_hash BLOB(64) NOT NULL,"
    "  output_index INTEGER NOT NULL,"
    "  created_at INTEGER NOT NULL,"
    "  UNIQUE(tx_hash, output_index)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_utxo_set_owner ON utxo_set(owner_fingerprint);"

    "CREATE TABLE IF NOT EXISTS epoch_signatures ("
    "  epoch INTEGER NOT NULL,"
    "  signer_id BLOB NOT NULL,"
    "  signature BLOB NOT NULL,"
    "  timestamp INTEGER NOT NULL,"
    "  PRIMARY KEY (epoch, signer_id)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_epoch_sigs_epoch ON epoch_signatures(epoch);"

    "CREATE TABLE IF NOT EXISTS blocks ("
    "  block_height INTEGER PRIMARY KEY,"
    "  prev_block_hash BLOB(64) NOT NULL,"
    "  state_root BLOB(64) NOT NULL,"
    "  tx_hash BLOB(64) NOT NULL,"
    "  tx_count INTEGER NOT NULL DEFAULT 1,"
    "  epoch INTEGER NOT NULL,"
    "  timestamp INTEGER NOT NULL,"
    "  proposer_id BLOB(32) NOT NULL,"
    "  block_hash BLOB(64) NOT NULL UNIQUE"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_blocks_hash ON blocks(block_hash);"
    "CREATE INDEX IF NOT EXISTS idx_blocks_epoch ON blocks(epoch);"

    "CREATE TABLE IF NOT EXISTS zone_metadata ("
    "  key TEXT PRIMARY KEY,"
    "  value BLOB NOT NULL"
    ");";

int dnac_zone_init_db(dnac_zone_t *zone, const char *db_path) {
    if (!zone || !db_path) return -1;

    strncpy(zone->db_path, db_path, sizeof(zone->db_path) - 1);

    int rc = sqlite3_open(db_path, &zone->db);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to open zone DB '%s': %s",
                      db_path, zone->db ? sqlite3_errmsg(zone->db) : "allocation failed");
        if (zone->db) {
            sqlite3_close(zone->db);
            zone->db = NULL;
        }
        return -1;
    }

    /* Enable WAL mode for better concurrent access */
    sqlite3_exec(zone->db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);

    /* Create schema */
    char *err_msg = NULL;
    rc = sqlite3_exec(zone->db, zone_schema, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create zone schema: %s", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(zone->db);
        zone->db = NULL;
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Zone DB initialized: %s", db_path);
    return 0;
}

/* ============================================================================
 * Zone Subsystem Init
 * ========================================================================== */

int dnac_zone_init_subsystems(dnac_zone_t *zone) {
    if (!zone || !zone->db) return -1;

    /* Load block tip height */
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(zone->db,
        "SELECT MAX(block_height) FROM blocks", -1, &stmt, NULL);

    if (rc == SQLITE_OK) {
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW && sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
            zone->block_height = (uint64_t)sqlite3_column_int64(stmt, 0);
        } else {
            zone->block_height = UINT64_MAX;
        }
        sqlite3_finalize(stmt);
    }

    /* Initialize UTXO state root by replaying all UTXOs */
    memset(zone->utxo_state_root, 0, 64);
    zone->state_root_initialized = 0;

    /* Replay UTXO adds for state root */
    rc = sqlite3_prepare_v2(zone->db,
        "SELECT nullifier FROM utxo_set ORDER BY tx_hash, output_index",
        -1, &stmt, NULL);

    if (rc == SQLITE_OK) {
        extern void qgp_sha3_512(const uint8_t *input, size_t len, uint8_t *output);

        int count = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const void *blob = sqlite3_column_blob(stmt, 0);
            int blob_size = sqlite3_column_bytes(stmt, 0);

            if (blob && blob_size == 64) {
                uint8_t op_input[65];
                op_input[0] = 'A';
                memcpy(op_input + 1, blob, 64);
                uint8_t op_hash[64];
                qgp_sha3_512(op_input, 65, op_hash);

                /* Update state root: new = SHA3-512(old || op_hash) */
                uint8_t combined[128];
                memcpy(combined, zone->utxo_state_root, 64);
                memcpy(combined + 64, op_hash, 64);
                qgp_sha3_512(combined, 128, zone->utxo_state_root);
                count++;
            }
        }
        sqlite3_finalize(stmt);
        zone->state_root_initialized = 1;

        QGP_LOG_INFO(LOG_TAG, "Zone '%s': state root from %d UTXOs, block height=%llu",
                     zone->zone_name, count,
                     zone->block_height == UINT64_MAX ? 0ULL :
                     (unsigned long long)zone->block_height);
    }

    /* Load Merkle state from checkpoint */
    memset(zone->merkle_root, 0, 64);
    zone->leaf_count = 0;
    zone->merkle_initialized = false;

    rc = sqlite3_prepare_v2(zone->db,
        "SELECT checkpoint_seq, merkle_root FROM ledger_checkpoints "
        "ORDER BY checkpoint_seq DESC LIMIT 1",
        -1, &stmt, NULL);

    if (rc == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            zone->leaf_count = (uint64_t)sqlite3_column_int64(stmt, 0);
            const void *root = sqlite3_column_blob(stmt, 1);
            if (root && sqlite3_column_bytes(stmt, 1) == 64) {
                memcpy(zone->merkle_root, root, 64);
            }
            zone->merkle_initialized = true;
        }
        sqlite3_finalize(stmt);
    }

    /* Count entries beyond checkpoint */
    rc = sqlite3_prepare_v2(zone->db,
        "SELECT COUNT(*) FROM ledger_entries WHERE sequence_number > ?",
        -1, &stmt, NULL);

    if (rc == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, (int64_t)zone->leaf_count);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            uint64_t extra = (uint64_t)sqlite3_column_int64(stmt, 0);
            zone->leaf_count += extra;
        }
        sqlite3_finalize(stmt);
        zone->merkle_initialized = true;
    }

    return 0;
}

/* ============================================================================
 * Zone Shutdown
 * ========================================================================== */

void dnac_zone_shutdown(dnac_zone_t *zone) {
    if (!zone) return;

    char hex[17];
    dnac_chain_id_short_hex(zone->chain_id, hex);
    QGP_LOG_INFO(LOG_TAG, "Shutting down zone '%s' (chain=%s)",
                 zone->zone_name, dnac_chain_id_is_zero(zone->chain_id) ? "pre-genesis" : hex);

    if (zone->bft_ctx) {
        dnac_bft_destroy(zone->bft_ctx);
        zone->bft_ctx = NULL;
    }

    if (zone->db) {
        sqlite3_close(zone->db);
        zone->db = NULL;
    }

    zone->active = false;
}

/* ============================================================================
 * Chain ID Persistence
 * ========================================================================== */

int dnac_zone_set_chain_id(dnac_zone_t *zone, const uint8_t *chain_id) {
    if (!zone || !chain_id || !zone->db) return -1;

    /* Update in-memory */
    memcpy(zone->chain_id, chain_id, DNAC_CHAIN_ID_SIZE);

    /* Persist to zone_metadata */
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(zone->db,
        "INSERT OR REPLACE INTO zone_metadata (key, value) VALUES ('chain_id', ?)",
        -1, &stmt, NULL);

    if (rc != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to prepare chain_id insert: %s",
                      sqlite3_errmsg(zone->db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, chain_id, DNAC_CHAIN_ID_SIZE, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to store chain_id: %s",
                      sqlite3_errmsg(zone->db));
        return -1;
    }

    char hex[17];
    dnac_chain_id_short_hex(chain_id, hex);
    QGP_LOG_INFO(LOG_TAG, "Zone '%s': chain_id set to %s...", zone->zone_name, hex);
    return 0;
}

int dnac_zone_load_chain_id(dnac_zone_t *zone) {
    if (!zone || !zone->db) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(zone->db,
        "SELECT value FROM zone_metadata WHERE key = 'chain_id'",
        -1, &stmt, NULL);

    if (rc != SQLITE_OK) return -1;

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;  /* No chain_id stored yet (pre-genesis) */
    }

    const void *blob = sqlite3_column_blob(stmt, 0);
    int blob_size = sqlite3_column_bytes(stmt, 0);

    if (blob && blob_size == DNAC_CHAIN_ID_SIZE) {
        memcpy(zone->chain_id, blob, DNAC_CHAIN_ID_SIZE);
        sqlite3_finalize(stmt);

        char hex[17];
        dnac_chain_id_short_hex(zone->chain_id, hex);
        QGP_LOG_INFO(LOG_TAG, "Zone '%s': loaded chain_id %s...", zone->zone_name, hex);
        return 0;
    }

    sqlite3_finalize(stmt);
    return -1;
}

/* ============================================================================
 * Data Directory Scanning
 * ========================================================================== */

int dnac_zone_scan_data_dir(dnac_zone_manager_t *mgr, const char *data_dir) {
    if (!mgr || !data_dir) return -1;

    strncpy(mgr->data_dir, data_dir, sizeof(mgr->data_dir) - 1);

    /* Always create the default zone from nullifiers.db */
    char default_db[600];
    snprintf(default_db, sizeof(default_db), "%s/nullifiers.db", data_dir);

    dnac_zone_t *default_zone = dnac_zone_create(mgr, "default", NULL);
    if (!default_zone) return -1;

    if (dnac_zone_init_db(default_zone, default_db) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to init default zone DB");
        return -1;
    }

    /* Try to load chain_id from DB (will be zeros if pre-genesis) */
    dnac_zone_load_chain_id(default_zone);

    /* Init subsystems */
    if (dnac_zone_init_subsystems(default_zone) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to init default zone subsystems");
        return -1;
    }

    int zone_count = 1;

    /* Scan for additional zone_*.db files */
    DIR *dir = opendir(data_dir);
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            /* Match zone_*.db pattern */
            if (strncmp(entry->d_name, "zone_", 5) != 0) continue;
            size_t len = strlen(entry->d_name);
            if (len < 9 || strcmp(entry->d_name + len - 3, ".db") != 0) continue;

            char zone_db[600];
            snprintf(zone_db, sizeof(zone_db), "%s/%s", data_dir, entry->d_name);

            /* Extract zone name from filename (zone_<hex>.db -> hex) */
            char zone_name[64];
            size_t name_len = len - 5 - 3;  /* remove "zone_" and ".db" */
            if (name_len > sizeof(zone_name) - 1) name_len = sizeof(zone_name) - 1;
            memcpy(zone_name, entry->d_name + 5, name_len);
            zone_name[name_len] = '\0';

            dnac_zone_t *zone = dnac_zone_create(mgr, zone_name, NULL);
            if (!zone) continue;

            if (dnac_zone_init_db(zone, zone_db) != 0) {
                QGP_LOG_WARN(LOG_TAG, "Failed to init zone DB: %s", zone_db);
                continue;
            }

            dnac_zone_load_chain_id(zone);

            if (dnac_zone_init_subsystems(zone) != 0) {
                QGP_LOG_WARN(LOG_TAG, "Failed to init zone subsystems: %s", zone_name);
                continue;
            }

            zone_count++;
        }
        closedir(dir);
    }

    QGP_LOG_INFO(LOG_TAG, "Scanned %s: found %d zone(s)", data_dir, zone_count);
    return zone_count;
}
