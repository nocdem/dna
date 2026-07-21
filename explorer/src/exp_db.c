/**
 * exp_db — DNAC Explorer sqlite index DB module.
 *
 * Prepared-statement pattern follows nodus/src/core/nodus_storage.c: every
 * statement used on a hot path is prepared once at open() and reused via
 * sqlite3_reset(); exp_db_verify_addr_stats (a diagnostic/audit call, not a
 * hot path) prepares its diff query ad-hoc, same as nodus_storage's
 * nodus_storage_count_key.
 */

#include "exp_db.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/utils/qgp_log.h"
#define LOG_TAG "EXP_DB"

/* ── Schema (design doc §3 + plan Task 2's txs.multi_signer / txs.raw) ── */

static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS blocks ("
    "  height     INTEGER PRIMARY KEY,"
    "  block_hash BLOB,"                 /* NULL until the child block is seen */
    "  tx_root    BLOB,"
    "  timestamp  INTEGER,"
    "  proposer   BLOB,"
    "  tx_count   INTEGER"
    ");"
    "CREATE TABLE IF NOT EXISTS txs ("
    "  hash         BLOB PRIMARY KEY,"
    "  seq          INTEGER UNIQUE,"     /* ledger sequence — total order */
    "  height       INTEGER,"
    "  tx_type      INTEGER,"
    "  fee          INTEGER,"
    "  size         INTEGER,"
    "  timestamp    INTEGER,"            /* from the deserialized TX, never envelope wall-clock */
    "  multi_signer INTEGER,"
    "  raw          BLOB"
    ");"
    "CREATE TABLE IF NOT EXISTS tx_io ("
    "  tx_hash   BLOB,"
    "  io_index  INTEGER,"
    "  direction INTEGER,"               /* 0=in 1=out */
    "  address   TEXT,"
    "  token_id  BLOB,"
    "  amount    INTEGER,"
    "  PRIMARY KEY(tx_hash, direction, io_index)"
    ");"
    "CREATE TABLE IF NOT EXISTS addr_stats ("
    "  address           TEXT,"
    "  token_id          BLOB,"
    "  balance           INTEGER,"       /* signed accumulation: credits - debits */
    "  tx_count          INTEGER,"
    "  first_seen_height INTEGER,"
    "  last_seen_height  INTEGER,"
    "  PRIMARY KEY(address, token_id)"
    ");"
    "CREATE TABLE IF NOT EXISTS meta ("
    "  key   TEXT PRIMARY KEY,"
    "  value BLOB"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_txs_height ON txs(height);"
    "CREATE INDEX IF NOT EXISTS idx_txs_seq ON txs(seq);"
    "CREATE INDEX IF NOT EXISTS idx_tx_io_addr ON tx_io(address, tx_hash);";

/* ── Prepared statement SQL ─────────────────────────────────────────── */

static const char *INSERT_BLOCK_SQL =
    "INSERT OR REPLACE INTO blocks (height, block_hash, tx_root, timestamp, proposer, tx_count) "
    "VALUES (?,?,?,?,?,?)";

static const char *SET_BLOCK_HASH_SQL =
    "UPDATE blocks SET block_hash = ? WHERE height = ?";

static const char *INSERT_TX_SQL =
    "INSERT OR IGNORE INTO txs (hash, seq, height, tx_type, fee, size, timestamp, multi_signer, raw) "
    "VALUES (?,?,?,?,?,?,?,?,?)";

static const char *INSERT_IO_SQL =
    "INSERT INTO tx_io (tx_hash, io_index, direction, address, token_id, amount) "
    "VALUES (?,?,?,?,?,?)";

/* ?1=address ?2=token_id ?3=signed delta ?4=tx_count delta (0 or 1, first-touch-in-this-tx)
 * ?5=height. Numbered params repeat intentionally (same bound value used in
 * both the INSERT branch and the ON CONFLICT UPDATE branch). */
static const char *UPSERT_ADDR_STATS_SQL =
    "INSERT INTO addr_stats(address, token_id, balance, tx_count, first_seen_height, last_seen_height) "
    "VALUES (?1, ?2, ?3, ?4, ?5, ?5) "
    "ON CONFLICT(address, token_id) DO UPDATE SET "
    "  balance = balance + ?3, "
    "  tx_count = tx_count + ?4, "
    "  first_seen_height = MIN(first_seen_height, ?5), "
    "  last_seen_height = MAX(last_seen_height, ?5)";

static const char *GET_META_SQL =
    "SELECT value FROM meta WHERE key = ?";

static const char *SET_META_SQL =
    "INSERT INTO meta(key, value) VALUES(?, ?) "
    "ON CONFLICT(key) DO UPDATE SET value = excluded.value";

/* Cursor: strict `height < ?1` — see exp_db.h header comment (genesis is
 * height 0, so 0 cannot be an "unbounded" sentinel; callers pass
 * UINT64_MAX for the first page). */
static const char *QUERY_BLOCKS_SQL =
    "SELECT height, block_hash, tx_root, timestamp, proposer, tx_count "
    "FROM blocks WHERE height < ? "
    "ORDER BY height DESC LIMIT ?";

static const char *QUERY_BLOCK_BY_HEIGHT_SQL =
    "SELECT height, block_hash, tx_root, timestamp, proposer, tx_count "
    "FROM blocks WHERE height = ?";

/* block_hash has no UNIQUE constraint in the spec'd schema; ORDER BY+LIMIT 1
 * keeps the (should-never-happen) collision case deterministic (D2). */
static const char *QUERY_BLOCK_BY_HASH_SQL =
    "SELECT height, block_hash, tx_root, timestamp, proposer, tx_count "
    "FROM blocks WHERE block_hash = ? "
    "ORDER BY height ASC LIMIT 1";

static const char *QUERY_TXS_BY_HEIGHT_SQL =
    "SELECT hash, seq, height, tx_type, fee, size, timestamp, multi_signer "
    "FROM txs WHERE height = ? "
    "ORDER BY seq ASC LIMIT ?";

static const char *QUERY_TX_SQL =
    "SELECT hash, seq, height, tx_type, fee, size, timestamp, multi_signer, raw "
    "FROM txs WHERE hash = ?";

static const char *QUERY_TX_IOS_SQL =
    "SELECT tx_hash, io_index, direction, address, token_id, amount "
    "FROM tx_io WHERE tx_hash = ? "
    "ORDER BY direction ASC, io_index ASC";

/* txs.seq is UNIQUE (ledger total order) so DESC-by-seq has no ties. */
static const char *QUERY_ADDRESS_SQL =
    "SELECT DISTINCT t.hash, t.seq, t.height, t.tx_type, t.fee, t.size, t.timestamp, t.multi_signer "
    "FROM txs t JOIN tx_io io ON io.tx_hash = t.hash "
    "WHERE io.address = ? AND t.seq < ? "
    "ORDER BY t.seq DESC LIMIT ?";

static const char *QUERY_BALANCE_SQL =
    "SELECT balance, tx_count FROM addr_stats WHERE address = ? AND token_id = ?";

/* ── DB handle ───────────────────────────────────────────────────────── */

struct exp_db {
    sqlite3 *conn;

    sqlite3_stmt *stmt_insert_block;
    sqlite3_stmt *stmt_set_block_hash;
    sqlite3_stmt *stmt_insert_tx;
    sqlite3_stmt *stmt_insert_io;
    sqlite3_stmt *stmt_upsert_addr_stats;
    sqlite3_stmt *stmt_get_meta;
    sqlite3_stmt *stmt_set_meta;
    sqlite3_stmt *stmt_query_blocks;
    sqlite3_stmt *stmt_query_block_by_height;
    sqlite3_stmt *stmt_query_block_by_hash;
    sqlite3_stmt *stmt_query_txs_by_height;
    sqlite3_stmt *stmt_query_tx;
    sqlite3_stmt *stmt_query_tx_ios;
    sqlite3_stmt *stmt_query_address;
    sqlite3_stmt *stmt_query_balance;
};

/* ── Row decode helpers ─────────────────────────────────────────────── */

static void row_to_block(sqlite3_stmt *s, exp_block_row_t *b) {
    memset(b, 0, sizeof(*b));
    b->height = (uint64_t)sqlite3_column_int64(s, 0);

    const void *bh = sqlite3_column_blob(s, 1);
    int bh_len = sqlite3_column_bytes(s, 1);
    if (bh && bh_len == 64) {
        memcpy(b->block_hash, bh, 64);
        b->has_block_hash = 1;
    }

    const void *tr = sqlite3_column_blob(s, 2);
    int tr_len = sqlite3_column_bytes(s, 2);
    if (tr && tr_len == 64) memcpy(b->tx_root, tr, 64);

    b->timestamp = (uint64_t)sqlite3_column_int64(s, 3);

    const void *pr = sqlite3_column_blob(s, 4);
    int pr_len = sqlite3_column_bytes(s, 4);
    if (pr && pr_len == 32) memcpy(b->proposer, pr, 32);

    b->tx_count = (uint32_t)sqlite3_column_int(s, 5);
}

/* Reads the shared 8-column tx projection (hash, seq, height, tx_type, fee,
 * size, timestamp, multi_signer) at columns 0..7. QUERY_TX_SQL has a 9th
 * (raw) column that callers read separately. */
static void row_to_tx(sqlite3_stmt *s, exp_tx_row_t *t) {
    memset(t, 0, sizeof(*t));

    const void *h = sqlite3_column_blob(s, 0);
    int h_len = sqlite3_column_bytes(s, 0);
    if (h && h_len == 64) memcpy(t->hash, h, 64);

    t->seq = (uint64_t)sqlite3_column_int64(s, 1);
    t->height = (uint64_t)sqlite3_column_int64(s, 2);
    t->tx_type = sqlite3_column_int(s, 3);
    t->fee = (uint64_t)sqlite3_column_int64(s, 4);
    t->size = (uint32_t)sqlite3_column_int(s, 5);
    t->timestamp = (uint64_t)sqlite3_column_int64(s, 6);
    t->multi_signer = sqlite3_column_int(s, 7);
}

static void row_to_io(sqlite3_stmt *s, exp_io_row_t *io) {
    memset(io, 0, sizeof(*io));

    const void *h = sqlite3_column_blob(s, 0);
    int h_len = sqlite3_column_bytes(s, 0);
    if (h && h_len == 64) memcpy(io->tx_hash, h, 64);

    io->io_index = sqlite3_column_int(s, 1);
    io->direction = sqlite3_column_int(s, 2);

    const unsigned char *addr = sqlite3_column_text(s, 3);
    if (addr) {
        strncpy(io->address, (const char *)addr, sizeof(io->address) - 1);
        io->address[sizeof(io->address) - 1] = '\0';
    }

    const void *tid = sqlite3_column_blob(s, 4);
    int tid_len = sqlite3_column_bytes(s, 4);
    if (tid && tid_len == 64) memcpy(io->token_id, tid, 64);

    io->amount = (uint64_t)sqlite3_column_int64(s, 5);
}

/* ── Open / close ────────────────────────────────────────────────────── */

int exp_db_open(const char *path, exp_db_t **db_out) {
    if (!path || !db_out) return -1;
    *db_out = NULL;

    exp_db_t *db = calloc(1, sizeof(*db));
    if (!db) return -1;

    if (sqlite3_open(path, &db->conn) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "open(%s) failed: %s", path, db->conn ? sqlite3_errmsg(db->conn) : "?");
        if (db->conn) sqlite3_close(db->conn);
        free(db);
        return -1;
    }

    /* WAL mode (no-op/ignored on ":memory:" — SQLite keeps in-memory journaling there). */
    sqlite3_exec(db->conn, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);
    sqlite3_exec(db->conn, "PRAGMA foreign_keys=ON", NULL, NULL, NULL);

    char *err = NULL;
    if (sqlite3_exec(db->conn, SCHEMA_SQL, NULL, NULL, &err) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "schema exec failed: %s", err ? err : "?");
        sqlite3_free(err);
        sqlite3_close(db->conn);
        free(db);
        return -1;
    }

    if (sqlite3_prepare_v2(db->conn, INSERT_BLOCK_SQL, -1, &db->stmt_insert_block, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, SET_BLOCK_HASH_SQL, -1, &db->stmt_set_block_hash, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, INSERT_TX_SQL, -1, &db->stmt_insert_tx, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, INSERT_IO_SQL, -1, &db->stmt_insert_io, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, UPSERT_ADDR_STATS_SQL, -1, &db->stmt_upsert_addr_stats, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, GET_META_SQL, -1, &db->stmt_get_meta, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, SET_META_SQL, -1, &db->stmt_set_meta, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, QUERY_BLOCKS_SQL, -1, &db->stmt_query_blocks, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, QUERY_BLOCK_BY_HEIGHT_SQL, -1, &db->stmt_query_block_by_height, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, QUERY_BLOCK_BY_HASH_SQL, -1, &db->stmt_query_block_by_hash, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, QUERY_TXS_BY_HEIGHT_SQL, -1, &db->stmt_query_txs_by_height, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, QUERY_TX_SQL, -1, &db->stmt_query_tx, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, QUERY_TX_IOS_SQL, -1, &db->stmt_query_tx_ios, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, QUERY_ADDRESS_SQL, -1, &db->stmt_query_address, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, QUERY_BALANCE_SQL, -1, &db->stmt_query_balance, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "prepare failed: %s", sqlite3_errmsg(db->conn));
        exp_db_close(db);
        return -1;
    }

    *db_out = db;
    return 0;
}

void exp_db_close(exp_db_t *db) {
    if (!db) return;

    if (db->stmt_insert_block) sqlite3_finalize(db->stmt_insert_block);
    if (db->stmt_set_block_hash) sqlite3_finalize(db->stmt_set_block_hash);
    if (db->stmt_insert_tx) sqlite3_finalize(db->stmt_insert_tx);
    if (db->stmt_insert_io) sqlite3_finalize(db->stmt_insert_io);
    if (db->stmt_upsert_addr_stats) sqlite3_finalize(db->stmt_upsert_addr_stats);
    if (db->stmt_get_meta) sqlite3_finalize(db->stmt_get_meta);
    if (db->stmt_set_meta) sqlite3_finalize(db->stmt_set_meta);
    if (db->stmt_query_blocks) sqlite3_finalize(db->stmt_query_blocks);
    if (db->stmt_query_block_by_height) sqlite3_finalize(db->stmt_query_block_by_height);
    if (db->stmt_query_block_by_hash) sqlite3_finalize(db->stmt_query_block_by_hash);
    if (db->stmt_query_txs_by_height) sqlite3_finalize(db->stmt_query_txs_by_height);
    if (db->stmt_query_tx) sqlite3_finalize(db->stmt_query_tx);
    if (db->stmt_query_tx_ios) sqlite3_finalize(db->stmt_query_tx_ios);
    if (db->stmt_query_address) sqlite3_finalize(db->stmt_query_address);
    if (db->stmt_query_balance) sqlite3_finalize(db->stmt_query_balance);

    if (db->conn) sqlite3_close(db->conn);
    free(db);
}

/* ── Blocks ──────────────────────────────────────────────────────────── */

int exp_db_insert_block(exp_db_t *db, const exp_block_row_t *b) {
    if (!db || !db->conn || !b) return -1;

    sqlite3_stmt *s = db->stmt_insert_block;
    sqlite3_reset(s);

    sqlite3_bind_int64(s, 1, (sqlite3_int64)b->height);
    if (b->has_block_hash)
        sqlite3_bind_blob(s, 2, b->block_hash, 64, SQLITE_STATIC);
    else
        sqlite3_bind_null(s, 2);
    sqlite3_bind_blob(s, 3, b->tx_root, 64, SQLITE_STATIC);
    sqlite3_bind_int64(s, 4, (sqlite3_int64)b->timestamp);
    sqlite3_bind_blob(s, 5, b->proposer, 32, SQLITE_STATIC);
    sqlite3_bind_int(s, 6, (int)b->tx_count);

    int rc = sqlite3_step(s);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "insert_block(%llu) failed: %s",
                      (unsigned long long)b->height, sqlite3_errmsg(db->conn));
        return -1;
    }
    return 0;
}

int exp_db_set_block_hash(exp_db_t *db, uint64_t height, const uint8_t hash[64]) {
    if (!db || !db->conn || !hash) return -1;

    sqlite3_stmt *s = db->stmt_set_block_hash;
    sqlite3_reset(s);

    sqlite3_bind_blob(s, 1, hash, 64, SQLITE_STATIC);
    sqlite3_bind_int64(s, 2, (sqlite3_int64)height);

    int rc = sqlite3_step(s);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "set_block_hash(%llu) failed: %s",
                      (unsigned long long)height, sqlite3_errmsg(db->conn));
        return -1;
    }
    return (sqlite3_changes(db->conn) > 0) ? 0 : -1;  /* height not found */
}

int exp_db_query_blocks(exp_db_t *db, uint64_t before_height, int limit, exp_block_row_t *rows, int *count_out) {
    if (!db || !db->conn || !rows || !count_out || limit <= 0) return -1;

    /* Defensive clamp: before_height is a user-supplied HTTP cursor
     * (Task 6). Values at/above 2^63 wrap to negative in sqlite3_bind_int64
     * and silently match nothing per the header's cursor contract; clamp
     * to INT64_MAX instead of letting a malformed cursor wrap. */
    if (before_height > (uint64_t)INT64_MAX) before_height = (uint64_t)INT64_MAX;

    sqlite3_stmt *s = db->stmt_query_blocks;
    sqlite3_reset(s);
    sqlite3_bind_int64(s, 1, (sqlite3_int64)before_height);
    sqlite3_bind_int(s, 2, limit);

    int n = 0;
    while (n < limit) {
        int rc = sqlite3_step(s);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            QGP_LOG_ERROR(LOG_TAG, "query_blocks step failed: %s", sqlite3_errmsg(db->conn));
            *count_out = n;
            return -1;
        }
        row_to_block(s, &rows[n]);
        n++;
    }
    *count_out = n;
    return 0;
}

int exp_db_query_block_by_height(exp_db_t *db, uint64_t height, exp_block_row_t *row_out) {
    if (!db || !db->conn || !row_out) return -1;

    sqlite3_stmt *s = db->stmt_query_block_by_height;
    sqlite3_reset(s);
    sqlite3_bind_int64(s, 1, (sqlite3_int64)height);

    int rc = sqlite3_step(s);
    if (rc != SQLITE_ROW) return -1;

    row_to_block(s, row_out);
    return 0;
}

int exp_db_query_block_by_hash(exp_db_t *db, const uint8_t hash[64], exp_block_row_t *row_out) {
    if (!db || !db->conn || !hash || !row_out) return -1;

    sqlite3_stmt *s = db->stmt_query_block_by_hash;
    sqlite3_reset(s);
    sqlite3_bind_blob(s, 1, hash, 64, SQLITE_STATIC);

    int rc = sqlite3_step(s);
    if (rc != SQLITE_ROW) return -1;

    row_to_block(s, row_out);
    return 0;
}

/* ── Transactions ────────────────────────────────────────────────────── */

int exp_db_insert_tx(exp_db_t *db, const exp_tx_row_t *tx,
                     const uint8_t *raw, size_t raw_len,
                     const exp_io_row_t *ios, int io_count) {
    if (!db || !db->conn || !tx) return -1;
    if (io_count < 0) return -1;
    if (io_count > 0 && !ios) return -1;

    char *err = NULL;
    if (sqlite3_exec(db->conn, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "insert_tx: BEGIN failed: %s", err ? err : "?");
        sqlite3_free(err);
        return -1;
    }

    sqlite3_stmt *s = db->stmt_insert_tx;
    sqlite3_reset(s);
    sqlite3_bind_blob(s, 1, tx->hash, 64, SQLITE_STATIC);
    sqlite3_bind_int64(s, 2, (sqlite3_int64)tx->seq);
    sqlite3_bind_int64(s, 3, (sqlite3_int64)tx->height);
    sqlite3_bind_int(s, 4, tx->tx_type);
    sqlite3_bind_int64(s, 5, (sqlite3_int64)tx->fee);
    sqlite3_bind_int(s, 6, (int)tx->size);
    sqlite3_bind_int64(s, 7, (sqlite3_int64)tx->timestamp);
    sqlite3_bind_int(s, 8, tx->multi_signer);
    if (raw && raw_len > 0)
        sqlite3_bind_blob(s, 9, raw, (int)raw_len, SQLITE_STATIC);
    else
        sqlite3_bind_null(s, 9);

    int rc = sqlite3_step(s);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "insert_tx: txs insert failed: %s", sqlite3_errmsg(db->conn));
        sqlite3_exec(db->conn, "ROLLBACK", NULL, NULL, NULL);
        return -1;
    }

    if (sqlite3_changes(db->conn) == 0) {
        /* duplicate txs.hash — no-op per INSERT OR IGNORE contract */
        if (sqlite3_exec(db->conn, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG, "insert_tx: COMMIT (dup) failed: %s", err ? err : "?");
            sqlite3_free(err);
            sqlite3_exec(db->conn, "ROLLBACK", NULL, NULL, NULL);
            return -1;
        }
        return 0;
    }

    for (int i = 0; i < io_count; i++) {
        const exp_io_row_t *io = &ios[i];

        sqlite3_stmt *is = db->stmt_insert_io;
        sqlite3_reset(is);
        /* Bind tx->hash, not io->tx_hash: the row's parent tx is the tx
         * being inserted in this call, never a caller-supplied io->tx_hash
         * (which is thereby ignored on insert) — eliminates the
         * foreign-hash divergence hazard where a caller-populated io row
         * could point tx_io at a different tx than the one it's nested
         * under. */
        sqlite3_bind_blob(is, 1, tx->hash, 64, SQLITE_STATIC);
        sqlite3_bind_int(is, 2, io->io_index);
        sqlite3_bind_int(is, 3, io->direction);
        sqlite3_bind_text(is, 4, io->address, -1, SQLITE_STATIC);
        sqlite3_bind_blob(is, 5, io->token_id, 64, SQLITE_STATIC);
        sqlite3_bind_int64(is, 6, (sqlite3_int64)io->amount);

        if (sqlite3_step(is) != SQLITE_DONE) {
            QGP_LOG_ERROR(LOG_TAG, "insert_tx: tx_io insert failed: %s", sqlite3_errmsg(db->conn));
            sqlite3_exec(db->conn, "ROLLBACK", NULL, NULL, NULL);
            return -1;
        }

        /* First-touch-in-this-tx detection for (address, token_id): tx_count
         * increments exactly once per distinct key touched by this tx,
         * matching exp_db_verify_addr_stats' COUNT(DISTINCT tx_hash) rule —
         * same derivation, two mechanics (brief, Task 2 Step 3). */
        int first_touch = 1;
        for (int j = 0; j < i; j++) {
            if (strcmp(ios[j].address, io->address) == 0 &&
                memcmp(ios[j].token_id, io->token_id, 64) == 0) {
                first_touch = 0;
                break;
            }
        }

        int64_t delta = (io->direction == 1) ? (int64_t)io->amount : -(int64_t)io->amount;

        sqlite3_stmt *as = db->stmt_upsert_addr_stats;
        sqlite3_reset(as);
        sqlite3_bind_text(as, 1, io->address, -1, SQLITE_STATIC);
        sqlite3_bind_blob(as, 2, io->token_id, 64, SQLITE_STATIC);
        sqlite3_bind_int64(as, 3, (sqlite3_int64)delta);
        sqlite3_bind_int(as, 4, first_touch ? 1 : 0);
        sqlite3_bind_int64(as, 5, (sqlite3_int64)tx->height);

        if (sqlite3_step(as) != SQLITE_DONE) {
            QGP_LOG_ERROR(LOG_TAG, "insert_tx: addr_stats upsert failed: %s", sqlite3_errmsg(db->conn));
            sqlite3_exec(db->conn, "ROLLBACK", NULL, NULL, NULL);
            return -1;
        }
    }

    if (sqlite3_exec(db->conn, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "insert_tx: COMMIT failed: %s", err ? err : "?");
        sqlite3_free(err);
        sqlite3_exec(db->conn, "ROLLBACK", NULL, NULL, NULL);
        return -1;
    }

    return 0;
}

int exp_db_query_txs_by_height(exp_db_t *db, uint64_t height, exp_tx_row_t *rows, int max, int *count_out) {
    if (!db || !db->conn || !rows || !count_out || max <= 0) return -1;

    sqlite3_stmt *s = db->stmt_query_txs_by_height;
    sqlite3_reset(s);
    sqlite3_bind_int64(s, 1, (sqlite3_int64)height);
    sqlite3_bind_int(s, 2, max);

    int n = 0;
    while (n < max) {
        int rc = sqlite3_step(s);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            QGP_LOG_ERROR(LOG_TAG, "query_txs_by_height step failed: %s", sqlite3_errmsg(db->conn));
            *count_out = n;
            return -1;
        }
        row_to_tx(s, &rows[n]);
        n++;
    }
    *count_out = n;
    return 0;
}

int exp_db_query_tx(exp_db_t *db, const uint8_t hash[64], exp_tx_row_t *tx_out,
                    exp_io_row_t *ios, int max_ios, int *io_count_out, uint8_t **raw_out, size_t *raw_len_out) {
    if (!db || !db->conn || !hash || !tx_out || !io_count_out) return -1;

    /* Initialize the out-params unconditionally (each guarded on its own
     * pointer, independent of the other) so the error path below can
     * safely test/free *raw_out even when a caller passes raw_out != NULL
     * with raw_len_out == NULL — previously *raw_out was left uninitialized
     * in that combination, making the error path's free() operate on
     * garbage. */
    if (raw_out) *raw_out = NULL;
    if (raw_len_out) *raw_len_out = 0;

    sqlite3_stmt *s = db->stmt_query_tx;
    sqlite3_reset(s);
    sqlite3_bind_blob(s, 1, hash, 64, SQLITE_STATIC);

    int rc = sqlite3_step(s);
    if (rc != SQLITE_ROW) {
        sqlite3_reset(s);
        return -1;
    }

    row_to_tx(s, tx_out);

    if (raw_out && raw_len_out) {
        const void *raw = sqlite3_column_blob(s, 8);
        int raw_len = sqlite3_column_bytes(s, 8);
        if (raw && raw_len > 0) {
            uint8_t *copy = malloc((size_t)raw_len);
            if (!copy) {
                sqlite3_reset(s);
                return -1;
            }
            memcpy(copy, raw, (size_t)raw_len);
            *raw_out = copy;
            *raw_len_out = (size_t)raw_len;
        } else {
            *raw_out = NULL;
            *raw_len_out = 0;
        }
    }

    sqlite3_reset(s);  /* release the read snapshot before opening a second statement */

    *io_count_out = 0;
    if (ios && max_ios > 0) {
        sqlite3_stmt *is = db->stmt_query_tx_ios;
        sqlite3_reset(is);
        sqlite3_bind_blob(is, 1, hash, 64, SQLITE_STATIC);

        int n = 0;
        while (n < max_ios) {
            int irc = sqlite3_step(is);
            if (irc == SQLITE_DONE) break;
            if (irc != SQLITE_ROW) {
                QGP_LOG_ERROR(LOG_TAG, "query_tx: ios step failed: %s", sqlite3_errmsg(db->conn));
                sqlite3_reset(is);
                if (raw_out && *raw_out) { free(*raw_out); *raw_out = NULL; }
                return -1;
            }
            row_to_io(is, &ios[n]);
            n++;
        }
        sqlite3_reset(is);
        *io_count_out = n;
    }

    return 0;
}

int exp_db_query_address(exp_db_t *db, const char *fp, uint64_t before_seq, int limit,
                         exp_tx_row_t *rows, int *count_out) {
    if (!db || !db->conn || !fp || !rows || !count_out || limit <= 0) return -1;

    /* Defensive clamp: before_seq is a user-supplied HTTP cursor (Task 6).
     * Values at/above 2^63 wrap to negative in sqlite3_bind_int64 and
     * silently match nothing per the header's cursor contract; clamp to
     * INT64_MAX instead of letting a malformed cursor wrap. */
    if (before_seq > (uint64_t)INT64_MAX) before_seq = (uint64_t)INT64_MAX;

    sqlite3_stmt *s = db->stmt_query_address;
    sqlite3_reset(s);
    sqlite3_bind_text(s, 1, fp, -1, SQLITE_STATIC);
    sqlite3_bind_int64(s, 2, (sqlite3_int64)before_seq);
    sqlite3_bind_int(s, 3, limit);

    int n = 0;
    while (n < limit) {
        int rc = sqlite3_step(s);
        if (rc == SQLITE_DONE) break;
        if (rc != SQLITE_ROW) {
            QGP_LOG_ERROR(LOG_TAG, "query_address step failed: %s", sqlite3_errmsg(db->conn));
            *count_out = n;
            return -1;
        }
        row_to_tx(s, &rows[n]);
        n++;
    }
    *count_out = n;
    return 0;
}

int exp_db_query_balance(exp_db_t *db, const char *fp, const uint8_t token_id[64], uint64_t *balance_out, uint64_t *txc_out) {
    if (!db || !db->conn || !fp || !token_id || !balance_out || !txc_out) return -1;

    sqlite3_stmt *s = db->stmt_query_balance;
    sqlite3_reset(s);
    sqlite3_bind_text(s, 1, fp, -1, SQLITE_STATIC);
    sqlite3_bind_blob(s, 2, token_id, 64, SQLITE_STATIC);

    int rc = sqlite3_step(s);
    if (rc == SQLITE_ROW) {
        /* balance is a signed accumulation (may be negative); reinterpret
         * the two's-complement bit pattern into the uint64_t out-param —
         * caller casts back to int64_t to recover the sign. */
        int64_t bal = sqlite3_column_int64(s, 0);
        *balance_out = (uint64_t)bal;
        *txc_out = (uint64_t)sqlite3_column_int64(s, 1);
    } else {
        /* No activity for this (address, token_id) — zero, not an error. */
        *balance_out = 0;
        *txc_out = 0;
    }
    return 0;
}

/* ── Meta ────────────────────────────────────────────────────────────── */

int exp_db_get_meta_u64(exp_db_t *db, const char *key, uint64_t *val_out) {
    if (!db || !db->conn || !key || !val_out) return -1;

    sqlite3_stmt *s = db->stmt_get_meta;
    sqlite3_reset(s);
    sqlite3_bind_text(s, 1, key, -1, SQLITE_STATIC);

    int rc = sqlite3_step(s);
    if (rc != SQLITE_ROW) return -1;
    if (sqlite3_column_type(s, 0) != SQLITE_INTEGER) return -1;

    *val_out = (uint64_t)sqlite3_column_int64(s, 0);
    return 0;
}

int exp_db_set_meta_u64(exp_db_t *db, const char *key, uint64_t val) {
    if (!db || !db->conn || !key) return -1;

    sqlite3_stmt *s = db->stmt_set_meta;
    sqlite3_reset(s);
    sqlite3_bind_text(s, 1, key, -1, SQLITE_STATIC);
    sqlite3_bind_int64(s, 2, (sqlite3_int64)val);

    int rc = sqlite3_step(s);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "set_meta_u64(%s) failed: %s", key, sqlite3_errmsg(db->conn));
        return -1;
    }
    return 0;
}

int exp_db_get_meta_blob(exp_db_t *db, const char *key, uint8_t *buf, size_t buflen, size_t *len_out) {
    if (!db || !db->conn || !key || !buf || !len_out) return -1;

    sqlite3_stmt *s = db->stmt_get_meta;
    sqlite3_reset(s);
    sqlite3_bind_text(s, 1, key, -1, SQLITE_STATIC);

    int rc = sqlite3_step(s);
    if (rc != SQLITE_ROW) return -1;
    if (sqlite3_column_type(s, 0) != SQLITE_BLOB) return -1;

    const void *blob = sqlite3_column_blob(s, 0);
    int blob_len = sqlite3_column_bytes(s, 0);
    if (blob_len < 0 || (size_t)blob_len > buflen) return -1;

    if (blob_len > 0 && blob) memcpy(buf, blob, (size_t)blob_len);
    *len_out = (size_t)blob_len;
    return 0;
}

int exp_db_set_meta_blob(exp_db_t *db, const char *key, const uint8_t *buf, size_t len) {
    if (!db || !db->conn || !key || (!buf && len > 0)) return -1;

    sqlite3_stmt *s = db->stmt_set_meta;
    sqlite3_reset(s);
    sqlite3_bind_text(s, 1, key, -1, SQLITE_STATIC);
    sqlite3_bind_blob(s, 2, buf, (int)len, SQLITE_STATIC);

    int rc = sqlite3_step(s);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "set_meta_blob(%s) failed: %s", key, sqlite3_errmsg(db->conn));
        return -1;
    }
    return 0;
}

/* ── D3: addr_stats symmetric-derivation verify ─────────────────────── */

int exp_db_verify_addr_stats(exp_db_t *db) {
    if (!db || !db->conn) return -1;

    char *err = NULL;

    sqlite3_exec(db->conn, "DROP TABLE IF EXISTS tmp_addr_recompute", NULL, NULL, NULL);

    /* Same credit/debit rule as the incremental path in exp_db_insert_tx:
     * balance = Σ(direction=1 amount) − Σ(direction=0 amount) per
     * (address, token_id); tx_count = COUNT(DISTINCT tx_hash) touching
     * that key — one derivation, two mechanics (D3). */
    static const char *RECOMPUTE_SQL =
        "CREATE TEMP TABLE tmp_addr_recompute AS "
        "SELECT tx_io.address AS address, tx_io.token_id AS token_id, "
        "       SUM(CASE WHEN tx_io.direction = 1 THEN tx_io.amount ELSE -tx_io.amount END) AS balance, "
        "       COUNT(DISTINCT tx_io.tx_hash) AS tx_count, "
        "       MIN(txs.height) AS first_seen_height, "
        "       MAX(txs.height) AS last_seen_height "
        "FROM tx_io JOIN txs ON tx_io.tx_hash = txs.hash "
        "GROUP BY tx_io.address, tx_io.token_id";

    if (sqlite3_exec(db->conn, RECOMPUTE_SQL, NULL, NULL, &err) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "verify_addr_stats: recompute failed: %s", err ? err : "?");
        sqlite3_free(err);
        return -1;
    }

    static const char *DIFF_SQL =
        "SELECT "
        "  (SELECT COUNT(*) FROM ("
        "     SELECT address,token_id,balance,tx_count,first_seen_height,last_seen_height FROM addr_stats "
        "     EXCEPT "
        "     SELECT address,token_id,balance,tx_count,first_seen_height,last_seen_height FROM tmp_addr_recompute)) "
        "+ "
        "  (SELECT COUNT(*) FROM ("
        "     SELECT address,token_id,balance,tx_count,first_seen_height,last_seen_height FROM tmp_addr_recompute "
        "     EXCEPT "
        "     SELECT address,token_id,balance,tx_count,first_seen_height,last_seen_height FROM addr_stats))";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db->conn, DIFF_SQL, -1, &stmt, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "verify_addr_stats: diff prepare failed: %s", sqlite3_errmsg(db->conn));
        sqlite3_exec(db->conn, "DROP TABLE IF EXISTS tmp_addr_recompute", NULL, NULL, NULL);
        return -1;
    }

    int mismatch = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        mismatch = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    sqlite3_exec(db->conn, "DROP TABLE IF EXISTS tmp_addr_recompute", NULL, NULL, NULL);

    if (mismatch < 0) return -1;
    return (mismatch == 0) ? 0 : -1;
}
