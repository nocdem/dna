/**
 * Nodus v5 — Witness Database Layer Implementation
 *
 * Consolidated SQLite operations for DNAC witness state.
 * Ported from dnac/src/witness/{nullifier,ledger,utxo_set,block}.c
 *
 * Key differences from DNAC originals:
 * - All functions take nodus_witness_t* instead of void* user_data
 * - Uses witness->db instead of global sqlite3* handles
 * - Single-zone (no zone.c abstraction)
 * - Uses fprintf logging (nodus convention)
 * - Simplified ledger (no Merkle tree — proof generation deferred)
 */

#include "witness/nodus_witness_db.h"
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <limits.h>

#define LOG_TAG "WITNESS_DB"

/* ── Nullifier operations ────────────────────────────────────────── */

bool nodus_witness_nullifier_exists(nodus_witness_t *w, const uint8_t *nullifier) {
    if (!w || !w->db || !nullifier) return false;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT 1 FROM nullifiers WHERE nullifier = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_blob(stmt, 1, nullifier, NODUS_T3_NULLIFIER_LEN, SQLITE_STATIC);
    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return exists;
}

int nodus_witness_nullifier_add(nodus_witness_t *w, const uint8_t *nullifier,
                                  const uint8_t *tx_hash) {
    if (!w || !w->db || !nullifier || !tx_hash) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT OR IGNORE INTO nullifiers (nullifier, tx_hash, added_at) "
        "VALUES (?, ?, ?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: nullifier insert prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, nullifier, NODUS_T3_NULLIFIER_LEN, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, tx_hash, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (int64_t)time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "%s: nullifier insert failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }
    return 0;
}

/* ── UTXO set operations ─────────────────────────────────────────── */

int nodus_witness_utxo_lookup(nodus_witness_t *w, const uint8_t *nullifier,
                                uint64_t *amount_out, char *owner_out) {
    if (!w || !w->db || !nullifier) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT amount, owner FROM utxo_set WHERE nullifier = ?",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, nullifier, NODUS_T3_NULLIFIER_LEN, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;  /* Not found */
    }

    if (amount_out)
        *amount_out = (uint64_t)sqlite3_column_int64(stmt, 0);

    if (owner_out) {
        const char *fp = (const char *)sqlite3_column_text(stmt, 1);
        if (fp) {
            strncpy(owner_out, fp, 128);
            owner_out[128] = '\0';
        }
    }

    sqlite3_finalize(stmt);
    return 0;
}

int nodus_witness_utxo_add(nodus_witness_t *w, const uint8_t *nullifier,
                              const char *owner, uint64_t amount,
                              const uint8_t *tx_hash, uint32_t index,
                              uint64_t block_height) {
    if (!w || !w->db || !nullifier || !owner || !tx_hash) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT OR IGNORE INTO utxo_set "
        "(nullifier, owner, amount, tx_hash, output_index, block_height, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: utxo add prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, nullifier, NODUS_T3_NULLIFIER_LEN, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, owner, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, (int64_t)amount);
    sqlite3_bind_blob(stmt, 4, tx_hash, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, (int)index);
    sqlite3_bind_int64(stmt, 6, (int64_t)block_height);
    sqlite3_bind_int64(stmt, 7, (int64_t)time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "%s: utxo add failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }
    return 0;
}

int nodus_witness_utxo_remove(nodus_witness_t *w, const uint8_t *nullifier) {
    if (!w || !w->db || !nullifier) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "DELETE FROM utxo_set WHERE nullifier = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, nullifier, NODUS_T3_NULLIFIER_LEN, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(w->db);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) return -1;
    if (changes == 0) return -1;  /* Not found */
    return 0;
}

int nodus_witness_utxo_count(nodus_witness_t *w, uint64_t *count_out) {
    if (!w || !w->db || !count_out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT COUNT(*) FROM utxo_set", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    if (sqlite3_step(stmt) == SQLITE_ROW)
        *count_out = (uint64_t)sqlite3_column_int64(stmt, 0);

    sqlite3_finalize(stmt);
    return 0;
}

int nodus_witness_utxo_by_owner(nodus_witness_t *w, const char *owner,
                                   nodus_witness_utxo_entry_t *out,
                                   int max_entries, int *count_out) {
    if (!w || !w->db || !owner || !out || !count_out || max_entries <= 0)
        return -1;

    *count_out = 0;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT nullifier, owner, amount, tx_hash, output_index, block_height "
        "FROM utxo_set WHERE owner = ? LIMIT ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, owner, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, max_entries);

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_entries) {
        nodus_witness_utxo_entry_t *e = &out[count];
        memset(e, 0, sizeof(*e));

        const void *blob;
        int blen;

        blob = sqlite3_column_blob(stmt, 0);
        blen = sqlite3_column_bytes(stmt, 0);
        if (blob && blen == NODUS_T3_NULLIFIER_LEN)
            memcpy(e->nullifier, blob, NODUS_T3_NULLIFIER_LEN);

        const char *fp = (const char *)sqlite3_column_text(stmt, 1);
        if (fp) { strncpy(e->owner, fp, sizeof(e->owner) - 1); }

        e->amount = (uint64_t)sqlite3_column_int64(stmt, 2);

        blob = sqlite3_column_blob(stmt, 3);
        blen = sqlite3_column_bytes(stmt, 3);
        if (blob && blen == NODUS_T3_TX_HASH_LEN)
            memcpy(e->tx_hash, blob, NODUS_T3_TX_HASH_LEN);

        e->output_index = (uint32_t)sqlite3_column_int(stmt, 4);
        e->block_height = (uint64_t)sqlite3_column_int64(stmt, 5);
        count++;
    }

    sqlite3_finalize(stmt);
    *count_out = count;
    return 0;
}

/* ── Ledger operations ───────────────────────────────────────────── */

int nodus_witness_ledger_add(nodus_witness_t *w, const uint8_t *tx_hash,
                                uint8_t tx_type, uint8_t nullifier_count) {
    if (!w || !w->db || !tx_hash) return -1;

    uint64_t now = (uint64_t)time(NULL);
    uint64_t epoch = now / NODUS_T3_EPOCH_DURATION_SEC;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT INTO ledger_entries (tx_hash, tx_type, epoch, timestamp, nullifier_count) "
        "VALUES (?, ?, ?, ?, ?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: ledger add prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, tx_hash, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, tx_type);
    sqlite3_bind_int64(stmt, 3, (int64_t)epoch);
    sqlite3_bind_int64(stmt, 4, (int64_t)now);
    sqlite3_bind_int(stmt, 5, nullifier_count);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "%s: ledger add failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }
    return 0;
}

static int ledger_from_row(sqlite3_stmt *stmt, nodus_witness_ledger_entry_t *out) {
    memset(out, 0, sizeof(*out));
    out->sequence = (uint64_t)sqlite3_column_int64(stmt, 0);

    const void *blob = sqlite3_column_blob(stmt, 1);
    int blen = sqlite3_column_bytes(stmt, 1);
    if (blob && blen == NODUS_T3_TX_HASH_LEN)
        memcpy(out->tx_hash, blob, NODUS_T3_TX_HASH_LEN);

    out->tx_type = (uint8_t)sqlite3_column_int(stmt, 2);
    out->epoch = (uint64_t)sqlite3_column_int64(stmt, 3);
    out->timestamp = (uint64_t)sqlite3_column_int64(stmt, 4);
    out->nullifier_count = (uint8_t)sqlite3_column_int(stmt, 5);
    return 0;
}

int nodus_witness_ledger_get(nodus_witness_t *w, uint64_t seq,
                                nodus_witness_ledger_entry_t *out) {
    if (!w || !w->db || !out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT sequence, tx_hash, tx_type, epoch, timestamp, nullifier_count "
        "FROM ledger_entries WHERE sequence = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, (int64_t)seq);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    ledger_from_row(stmt, out);
    sqlite3_finalize(stmt);
    return 0;
}

int nodus_witness_ledger_get_by_hash(nodus_witness_t *w, const uint8_t *tx_hash,
                                        nodus_witness_ledger_entry_t *out) {
    if (!w || !w->db || !tx_hash || !out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT sequence, tx_hash, tx_type, epoch, timestamp, nullifier_count "
        "FROM ledger_entries WHERE tx_hash = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, tx_hash, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    ledger_from_row(stmt, out);
    sqlite3_finalize(stmt);
    return 0;
}

int nodus_witness_ledger_get_range(nodus_witness_t *w, uint64_t from, uint64_t to,
                                      nodus_witness_ledger_entry_t *out,
                                      int max_entries, int *count_out) {
    if (!w || !w->db || !out || !count_out || max_entries <= 0) return -1;
    *count_out = 0;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT sequence, tx_hash, tx_type, epoch, timestamp, nullifier_count "
        "FROM ledger_entries WHERE sequence >= ? AND sequence <= ? "
        "ORDER BY sequence ASC LIMIT ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, (int64_t)from);
    sqlite3_bind_int64(stmt, 2, (int64_t)to);
    sqlite3_bind_int(stmt, 3, max_entries);

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < max_entries) {
        ledger_from_row(stmt, &out[count]);
        count++;
    }

    sqlite3_finalize(stmt);
    *count_out = count;
    return 0;
}

uint64_t nodus_witness_ledger_count(nodus_witness_t *w) {
    if (!w || !w->db) return 0;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT COUNT(*) FROM ledger_entries", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;

    uint64_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = (uint64_t)sqlite3_column_int64(stmt, 0);

    sqlite3_finalize(stmt);
    return count;
}

/* ── Block operations ────────────────────────────────────────────── */

int nodus_witness_block_add(nodus_witness_t *w, const uint8_t *tx_hash,
                               uint8_t tx_type, uint64_t timestamp,
                               const uint8_t *proposer_id) {
    if (!w || !w->db || !tx_hash) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT INTO blocks (tx_hash, tx_type, timestamp, proposer_id, created_at) "
        "VALUES (?, ?, ?, ?, ?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: block add prepare failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, tx_hash, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, tx_type);
    sqlite3_bind_int64(stmt, 3, (int64_t)timestamp);
    if (proposer_id)
        sqlite3_bind_blob(stmt, 4, proposer_id, NODUS_T3_WITNESS_ID_LEN, SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 4);
    sqlite3_bind_int64(stmt, 5, (int64_t)time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "%s: block add failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }
    return 0;
}

static int block_from_row(sqlite3_stmt *stmt, nodus_witness_block_t *out) {
    memset(out, 0, sizeof(*out));
    out->height = (uint64_t)sqlite3_column_int64(stmt, 0);

    const void *blob = sqlite3_column_blob(stmt, 1);
    int blen = sqlite3_column_bytes(stmt, 1);
    if (blob && blen == NODUS_T3_TX_HASH_LEN)
        memcpy(out->tx_hash, blob, NODUS_T3_TX_HASH_LEN);

    out->tx_type = (uint8_t)sqlite3_column_int(stmt, 2);
    out->timestamp = (uint64_t)sqlite3_column_int64(stmt, 3);

    blob = sqlite3_column_blob(stmt, 4);
    blen = sqlite3_column_bytes(stmt, 4);
    if (blob && blen == NODUS_T3_WITNESS_ID_LEN)
        memcpy(out->proposer_id, blob, NODUS_T3_WITNESS_ID_LEN);

    return 0;
}

int nodus_witness_block_get(nodus_witness_t *w, uint64_t height,
                               nodus_witness_block_t *out) {
    if (!w || !w->db || !out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT height, tx_hash, tx_type, timestamp, proposer_id "
        "FROM blocks WHERE height = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, (int64_t)height);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    block_from_row(stmt, out);
    sqlite3_finalize(stmt);
    return 0;
}

int nodus_witness_block_get_latest(nodus_witness_t *w,
                                      nodus_witness_block_t *out) {
    if (!w || !w->db || !out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT height, tx_hash, tx_type, timestamp, proposer_id "
        "FROM blocks ORDER BY height DESC LIMIT 1", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    block_from_row(stmt, out);
    sqlite3_finalize(stmt);
    return 0;
}

uint64_t nodus_witness_block_height(nodus_witness_t *w) {
    if (!w || !w->db) return 0;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT MAX(height) FROM blocks", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return 0;

    uint64_t height = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW &&
        sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
        height = (uint64_t)sqlite3_column_int64(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return height;
}

/* ── Genesis state ───────────────────────────────────────────────── */

bool nodus_witness_genesis_exists(nodus_witness_t *w) {
    if (!w || !w->db) return false;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT 1 FROM genesis_state WHERE id = 1", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return false;

    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return exists;
}

int nodus_witness_genesis_set(nodus_witness_t *w, const uint8_t *tx_hash,
                                 uint64_t total_supply,
                                 const uint8_t *commitment) {
    if (!w || !w->db || !tx_hash) return -1;

    if (nodus_witness_genesis_exists(w)) {
        fprintf(stderr, "%s: genesis already exists\n", LOG_TAG);
        return -2;
    }

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT INTO genesis_state (id, tx_hash, total_supply, commitment, created_at) "
        "VALUES (1, ?, ?, ?, ?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, tx_hash, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, (int64_t)total_supply);
    if (commitment)
        sqlite3_bind_blob(stmt, 3, commitment, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);
    else
        sqlite3_bind_null(stmt, 3);
    sqlite3_bind_int64(stmt, 4, (int64_t)time(NULL));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) return -1;

    fprintf(stderr, "%s: genesis recorded: supply=%llu\n",
            LOG_TAG, (unsigned long long)total_supply);
    return 0;
}

int nodus_witness_genesis_get(nodus_witness_t *w,
                                 nodus_witness_genesis_t *out) {
    if (!w || !w->db || !out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT tx_hash, total_supply, created_at "
        "FROM genesis_state WHERE id = 1", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    memset(out, 0, sizeof(*out));
    const void *blob = sqlite3_column_blob(stmt, 0);
    int blen = sqlite3_column_bytes(stmt, 0);
    if (blob && blen == NODUS_T3_TX_HASH_LEN)
        memcpy(out->tx_hash, blob, NODUS_T3_TX_HASH_LEN);

    out->total_supply = (uint64_t)sqlite3_column_int64(stmt, 1);
    out->timestamp = (uint64_t)sqlite3_column_int64(stmt, 2);

    sqlite3_finalize(stmt);
    return 0;
}

/* ── Supply tracking ─────────────────────────────────────────────── */

int nodus_witness_supply_init(nodus_witness_t *w, uint64_t total_supply,
                                 const uint8_t *genesis_tx_hash) {
    if (!w || !w->db || !genesis_tx_hash) return -1;

    /* Check if already initialized */
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT 1 FROM supply_tracking WHERE id = 1", -1, &stmt, NULL);
    if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -2;  /* Already initialized */
    }
    sqlite3_finalize(stmt);

    /* Need the supply_tracking table */
    sqlite3_exec(w->db,
        "CREATE TABLE IF NOT EXISTS supply_tracking ("
        "  id INTEGER PRIMARY KEY CHECK(id = 1),"
        "  genesis_supply INTEGER NOT NULL,"
        "  total_burned INTEGER NOT NULL DEFAULT 0,"
        "  current_supply INTEGER NOT NULL,"
        "  last_tx_hash BLOB NOT NULL,"
        "  last_sequence INTEGER NOT NULL"
        ");", NULL, NULL, NULL);

    rc = sqlite3_prepare_v2(w->db,
        "INSERT INTO supply_tracking (id, genesis_supply, total_burned, "
        "current_supply, last_tx_hash, last_sequence) VALUES (1, ?, 0, ?, ?, 1)",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int64(stmt, 1, (int64_t)total_supply);
    sqlite3_bind_int64(stmt, 2, (int64_t)total_supply);
    sqlite3_bind_blob(stmt, 3, genesis_tx_hash, NODUS_T3_TX_HASH_LEN, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int nodus_witness_supply_get(nodus_witness_t *w,
                                nodus_witness_supply_t *out) {
    if (!w || !w->db || !out) return -1;

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT genesis_supply, total_burned, current_supply, last_sequence "
        "FROM supply_tracking WHERE id = 1", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->genesis_supply = (uint64_t)sqlite3_column_int64(stmt, 0);
    out->total_burned = (uint64_t)sqlite3_column_int64(stmt, 1);
    out->current_supply = (uint64_t)sqlite3_column_int64(stmt, 2);
    out->last_sequence = (uint64_t)sqlite3_column_int64(stmt, 3);

    sqlite3_finalize(stmt);
    return 0;
}

/* ── DB transaction wrappers ─────────────────────────────────────── */

int nodus_witness_db_begin(nodus_witness_t *w) {
    if (!w || !w->db) return -1;
    char *err = NULL;
    int rc = sqlite3_exec(w->db, "BEGIN TRANSACTION", NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: BEGIN failed: %s\n", LOG_TAG, err);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

int nodus_witness_db_commit(nodus_witness_t *w) {
    if (!w || !w->db) return -1;
    char *err = NULL;
    int rc = sqlite3_exec(w->db, "COMMIT", NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: COMMIT failed: %s\n", LOG_TAG, err);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

int nodus_witness_db_rollback(nodus_witness_t *w) {
    if (!w || !w->db) return -1;
    char *err = NULL;
    int rc = sqlite3_exec(w->db, "ROLLBACK", NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: ROLLBACK failed: %s\n", LOG_TAG, err);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}
