/**
 * exp_db — DNAC Explorer sqlite index DB module (index schema v2). See
 * exp_db.h for the schema, the rebuild-on-version-mismatch rule and the
 * consumed-coin resolution rule.
 *
 * Prepared-statement pattern follows nodus/src/core/nodus_storage.c: every
 * statement used on a hot path is prepared once at open() and reused via
 * sqlite3_reset(); exp_db_verify_index (a diagnostic call, not a hot path)
 * prepares its checks ad-hoc.
 */

#include "exp_db.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/utils/qgp_log.h"
#define LOG_TAG "EXP_DB"

/* ── Schema v2 ──────────────────────────────────────────────────────── */

/* Every table the explorer has ever created, v1 (ledger-sequence index:
 * blocks/txs/tx_io/addr_stats) and v2. A schema-version mismatch drops
 * them all before SCHEMA_SQL recreates v2 — the index is derived data. */
static const char *DROP_ALL_SQL =
    "DROP TABLE IF EXISTS addr_stats;"
    "DROP TABLE IF EXISTS tx_io;"
    "DROP TABLE IF EXISTS txs;"
    "DROP TABLE IF EXISTS item_names;"
    "DROP TABLE IF EXISTS item_records;"
    "DROP TABLE IF EXISTS item_io;"
    "DROP TABLE IF EXISTS items;"
    "DROP TABLE IF EXISTS blocks;"
    "DROP TABLE IF EXISTS meta;";

/* SYSTEM records live in their own typed table (item_records), not in a
 * JSON column: the address history must find an item by the record's
 * validator / delegator / destination fingerprint, which wants a plain
 * indexed column; typed columns also keep the stored form a direct copy
 * of the decoded fields (no second encoding to parse back on read) and
 * need no JSON1 extension in the linked sqlite. */
static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS meta ("
    "  key   TEXT PRIMARY KEY,"
    "  value BLOB"
    ");"
    "CREATE TABLE IF NOT EXISTS blocks ("
    "  height        INTEGER PRIMARY KEY,"
    "  block_id      BLOB NOT NULL,"
    "  prev_id       BLOB NOT NULL,"
    "  time_ms       INTEGER NOT NULL,"
    "  proposer      BLOB NOT NULL,"
    "  global_root   BLOB NOT NULL,"
    "  applied_count INTEGER NOT NULL,"
    "  n_items       INTEGER NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS items ("
    "  height      INTEGER NOT NULL,"
    "  idx         INTEGER NOT NULL,"
    "  kind        INTEGER NOT NULL,"
    "  code        INTEGER NOT NULL,"
    "  wire_id     BLOB,"                  /* NULL = absent (refused envelope) */
    "  intent_id   BLOB,"                  /* NULL = absent (not an applied envelope) */
    "  fee         INTEGER,"               /* NULL = absent */
    "  op          TEXT,"                  /* NULL = unnamed */
    "  has_effects INTEGER NOT NULL,"
    "  burned      INTEGER NOT NULL,"
    "  PRIMARY KEY(height, idx)"
    ");"
    "CREATE TABLE IF NOT EXISTS item_io ("
    "  height       INTEGER NOT NULL,"
    "  idx          INTEGER NOT NULL,"
    "  dir          INTEGER NOT NULL,"     /* 0 consumed, 1 created */
    "  pos          INTEGER NOT NULL,"     /* call order within (item, dir) */
    "  coin_id      BLOB NOT NULL,"
    "  address      TEXT,"                 /* NULL = consumed, creator not indexed */
    "  token        BLOB,"
    "  amount       INTEGER,"
    "  unlock_block INTEGER,"
    "  PRIMARY KEY(height, idx, dir, pos)"
    ");"
    "CREATE TABLE IF NOT EXISTS item_records ("
    "  height         INTEGER NOT NULL,"
    "  idx            INTEGER NOT NULL,"
    "  kind           INTEGER NOT NULL,"
    "  validator      TEXT,"
    "  delegator      TEXT,"
    "  dest           TEXT,"
    "  amount         INTEGER NOT NULL,"
    "  commission_bps INTEGER NOT NULL,"
    "  param_id       INTEGER NOT NULL,"
    "  new_value      INTEGER NOT NULL,"
    "  effective      INTEGER NOT NULL,"
    "  PRIMARY KEY(height, idx)"
    ");"
    /* HF-4 (exp_db.h): one row per applied NAME_REGISTER item. Created IF
     * NOT EXISTS on every open — an existing v2 index gains it unchanged. */
    "CREATE TABLE IF NOT EXISTS item_names ("
    "  height INTEGER NOT NULL,"
    "  idx    INTEGER NOT NULL,"
    "  name   TEXT NOT NULL,"
    "  price  INTEGER NOT NULL,"
    "  owner  TEXT,"                       /* NULL = first input's creator not indexed */
    "  PRIMARY KEY(height, idx)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_blocks_id ON blocks(block_id);"
    "CREATE INDEX IF NOT EXISTS idx_items_wire ON items(wire_id);"
    "CREATE INDEX IF NOT EXISTS idx_items_intent ON items(intent_id);"
    "CREATE INDEX IF NOT EXISTS idx_io_coin ON item_io(coin_id, dir);"
    "CREATE INDEX IF NOT EXISTS idx_io_addr ON item_io(address);"
    "CREATE INDEX IF NOT EXISTS idx_rec_validator ON item_records(validator);"
    "CREATE INDEX IF NOT EXISTS idx_rec_delegator ON item_records(delegator);"
    "CREATE INDEX IF NOT EXISTS idx_rec_dest ON item_records(dest);"
    "CREATE INDEX IF NOT EXISTS idx_names_name ON item_names(name);";

/* ── Prepared statement SQL ─────────────────────────────────────────── */

static const char *INSERT_BLOCK_SQL =
    "INSERT INTO blocks (height, block_id, prev_id, time_ms, proposer, global_root, "
    "applied_count, n_items) VALUES (?,?,?,?,?,?,?,?)";

static const char *INSERT_ITEM_SQL =
    "INSERT INTO items (height, idx, kind, code, wire_id, intent_id, fee, op, "
    "has_effects, burned) VALUES (?,?,?,?,?,?,?,?,?,?)";

static const char *INSERT_RECORD_SQL =
    "INSERT INTO item_records (height, idx, kind, validator, delegator, dest, amount, "
    "commission_bps, param_id, new_value, effective) VALUES (?,?,?,?,?,?,?,?,?,?,?)";

static const char *INSERT_IO_SQL =
    "INSERT INTO item_io (height, idx, dir, pos, coin_id, address, token, amount, "
    "unlock_block) VALUES (?,?,?,?,?,?,?,?,?)";

/* HF-4: the owner is the resolved address of the item's first consumed
 * coin, written just before in the same transaction (exp_db.h item_names). */
static const char *INSERT_NAME_SQL =
    "INSERT INTO item_names (height, idx, name, price, owner) VALUES (?1, ?2, ?3, ?4, "
    "(SELECT address FROM item_io WHERE height = ?1 AND idx = ?2 AND dir = 0 AND pos = 0))";

/* The creating row of a coin. A coin id is created once (the utxo_set
 * key); ORDER BY + LIMIT 1 keeps a (never expected) duplicate
 * deterministic. */
static const char *RESOLVE_COIN_SQL =
    "SELECT address, token, amount FROM item_io WHERE coin_id = ? AND dir = 1 "
    "ORDER BY height ASC, idx ASC, pos ASC LIMIT 1";

static const char *GET_META_SQL =
    "SELECT value FROM meta WHERE key = ?";

static const char *SET_META_SQL =
    "INSERT INTO meta(key, value) VALUES(?, ?) "
    "ON CONFLICT(key) DO UPDATE SET value = excluded.value";

#define BLOCK_COLS \
    "height, block_id, prev_id, time_ms, proposer, global_root, applied_count, n_items"

static const char *QUERY_BLOCKS_SQL =
    "SELECT " BLOCK_COLS " FROM blocks WHERE height < ? ORDER BY height DESC LIMIT ?";

static const char *QUERY_BLOCK_BY_HEIGHT_SQL =
    "SELECT " BLOCK_COLS " FROM blocks WHERE height = ?";

static const char *QUERY_BLOCK_BY_ID_SQL =
    "SELECT " BLOCK_COLS " FROM blocks WHERE block_id = ? ORDER BY height ASC LIMIT 1";

#define ITEM_COLS \
    "i.height, i.idx, i.kind, i.code, i.wire_id, i.intent_id, i.fee, i.op, " \
    "i.has_effects, i.burned, r.kind, r.validator, r.delegator, r.dest, r.amount, " \
    "r.commission_bps, r.param_id, r.new_value, r.effective, b.time_ms, " \
    "n.name, n.price, n.owner"

#define ITEM_JOINS \
    "JOIN blocks b ON b.height = i.height " \
    "LEFT JOIN item_records r ON r.height = i.height AND r.idx = i.idx " \
    "LEFT JOIN item_names n ON n.height = i.height AND n.idx = i.idx "

#define ITEM_FROM " FROM items i " ITEM_JOINS

static const char *QUERY_ITEMS_SQL =
    "SELECT " ITEM_COLS ITEM_FROM
    "WHERE i.height = ? AND i.idx >= ? ORDER BY i.idx ASC LIMIT ?";

static const char *QUERY_ITEM_SQL =
    "SELECT " ITEM_COLS ITEM_FROM "WHERE i.height = ? AND i.idx = ?";

static const char *QUERY_ITEM_BY_ID_SQL =
    "SELECT " ITEM_COLS ITEM_FROM
    "WHERE i.wire_id = ?1 OR i.intent_id = ?1 ORDER BY i.height ASC, i.idx ASC LIMIT 1";

static const char *QUERY_ITEM_BY_NAME_SQL =
    "SELECT " ITEM_COLS ITEM_FROM
    "WHERE n.name = ?1 ORDER BY i.height ASC, i.idx ASC LIMIT 1";

static const char *QUERY_IOS_SQL =
    "SELECT height, idx, dir, pos, coin_id, address, token, amount, unlock_block "
    "FROM item_io WHERE height = ? AND idx = ? ORDER BY dir ASC, pos ASC LIMIT ?";

/* UNION de-duplicates an item that touches the address more than once. */
static const char *QUERY_ADDRESS_SQL =
    "SELECT " ITEM_COLS " FROM ("
    "  SELECT height, idx FROM item_io WHERE address = ?1 "
    "  UNION "
    "  SELECT height, idx FROM item_records WHERE validator = ?1 OR delegator = ?1 OR dest = ?1"
    ") t JOIN items i ON i.height = t.height AND i.idx = t.idx "
    ITEM_JOINS
    "WHERE i.height < ?2 OR (i.height = ?2 AND i.idx < ?3) "
    "ORDER BY i.height DESC, i.idx DESC LIMIT ?4";

/* ── DB handle ───────────────────────────────────────────────────────── */

struct exp_db {
    sqlite3 *conn;

    sqlite3_stmt *stmt_insert_block;
    sqlite3_stmt *stmt_insert_item;
    sqlite3_stmt *stmt_insert_record;
    sqlite3_stmt *stmt_insert_io;
    sqlite3_stmt *stmt_insert_name;
    sqlite3_stmt *stmt_resolve_coin;
    sqlite3_stmt *stmt_get_meta;
    sqlite3_stmt *stmt_set_meta;
    sqlite3_stmt *stmt_query_blocks;
    sqlite3_stmt *stmt_query_block_by_height;
    sqlite3_stmt *stmt_query_block_by_id;
    sqlite3_stmt *stmt_query_items;
    sqlite3_stmt *stmt_query_item;
    sqlite3_stmt *stmt_query_item_by_id;
    sqlite3_stmt *stmt_query_item_by_name;
    sqlite3_stmt *stmt_query_ios;
    sqlite3_stmt *stmt_query_address;
};

/* ── Batch ───────────────────────────────────────────────────────────── */

void exp_block_batch_init(exp_block_batch_t *b) {
    if (!b) return;
    memset(b, 0, sizeof(*b));
}

void exp_block_batch_free(exp_block_batch_t *b) {
    if (!b) return;
    free(b->items);
    free(b->ios);
    memset(b, 0, sizeof(*b));
}

/* ── Row decode helpers ─────────────────────────────────────────────── */

static int col_blob64(sqlite3_stmt *s, int col, uint8_t out[64]) {
    const void *p = sqlite3_column_blob(s, col);
    int n = sqlite3_column_bytes(s, col);
    if (p && n == 64) {
        memcpy(out, p, 64);
        return 1;
    }
    return 0;
}

static void col_text129(sqlite3_stmt *s, int col, char out[129]) {
    const unsigned char *p = sqlite3_column_text(s, col);
    out[0] = '\0';
    if (p) {
        strncpy(out, (const char *)p, 128);
        out[128] = '\0';
    }
}

static void row_to_block(sqlite3_stmt *s, exp_block_row_t *b) {
    memset(b, 0, sizeof(*b));
    b->height = (uint64_t)sqlite3_column_int64(s, 0);
    col_blob64(s, 1, b->block_id);
    col_blob64(s, 2, b->prev_id);
    b->time_ms = (uint64_t)sqlite3_column_int64(s, 3);

    const void *pr = sqlite3_column_blob(s, 4);
    int pr_len = sqlite3_column_bytes(s, 4);
    if (pr && pr_len > 0 && pr_len <= 64) {
        memcpy(b->proposer, pr, (size_t)pr_len);
        b->proposer_len = (uint32_t)pr_len;
    }

    col_blob64(s, 5, b->global_root);
    b->applied_count = (uint64_t)sqlite3_column_int64(s, 6);
    b->n_items = (uint32_t)sqlite3_column_int64(s, 7);
}

/* The ITEM_COLS projection (23 columns). */
static void row_to_item(sqlite3_stmt *s, exp_item_row_t *it) {
    memset(it, 0, sizeof(*it));
    it->height = (uint64_t)sqlite3_column_int64(s, 0);
    it->idx = (uint32_t)sqlite3_column_int64(s, 1);
    it->kind = sqlite3_column_int(s, 2);
    it->code = (uint32_t)sqlite3_column_int64(s, 3);
    it->has_wire_id = col_blob64(s, 4, it->wire_id);
    it->has_intent_id = col_blob64(s, 5, it->intent_id);
    if (sqlite3_column_type(s, 6) != SQLITE_NULL) {
        it->has_fee = 1;
        it->fee = (uint64_t)sqlite3_column_int64(s, 6);
    }
    const unsigned char *op = sqlite3_column_text(s, 7);
    if (op) {
        strncpy(it->op, (const char *)op, sizeof(it->op) - 1);
        it->op[sizeof(it->op) - 1] = '\0';
    }
    it->has_effects = sqlite3_column_int(s, 8);
    it->burned = (uint64_t)sqlite3_column_int64(s, 9);

    if (sqlite3_column_type(s, 10) != SQLITE_NULL) {
        it->rec.kind = sqlite3_column_int(s, 10);
        col_text129(s, 11, it->rec.validator);
        col_text129(s, 12, it->rec.delegator);
        col_text129(s, 13, it->rec.dest);
        it->rec.amount = (uint64_t)sqlite3_column_int64(s, 14);
        it->rec.commission_bps = (uint32_t)sqlite3_column_int64(s, 15);
        it->rec.param_id = (uint32_t)sqlite3_column_int64(s, 16);
        it->rec.new_value = (uint64_t)sqlite3_column_int64(s, 17);
        it->rec.effective = (uint64_t)sqlite3_column_int64(s, 18);
    }
    it->block_time_ms = (uint64_t)sqlite3_column_int64(s, 19);
    /* HF-4 NAME_REGISTER (item_names, LEFT JOIN: NULL = not a registration) */
    const unsigned char *nm = sqlite3_column_text(s, 20);
    if (nm) {
        strncpy(it->name, (const char *)nm, sizeof(it->name) - 1);
        it->name[sizeof(it->name) - 1] = '\0';
        it->name_price = (uint64_t)sqlite3_column_int64(s, 21);
        col_text129(s, 22, it->name_owner);
    }
}

static void row_to_io(sqlite3_stmt *s, exp_io_row_t *io) {
    memset(io, 0, sizeof(*io));
    io->height = (uint64_t)sqlite3_column_int64(s, 0);
    io->idx = (uint32_t)sqlite3_column_int64(s, 1);
    io->dir = sqlite3_column_int(s, 2);
    io->pos = (uint32_t)sqlite3_column_int64(s, 3);
    col_blob64(s, 4, io->coin_id);
    if (sqlite3_column_type(s, 5) != SQLITE_NULL) {
        io->has_owner = 1;
        col_text129(s, 5, io->address);
        col_blob64(s, 6, io->token_id);
        io->amount = (uint64_t)sqlite3_column_int64(s, 7);
    }
    io->unlock_block = (uint64_t)sqlite3_column_int64(s, 8);
}

/* ── Open / close ────────────────────────────────────────────────────── */

/* Reads meta "schema_version" straight off the connection (the prepared
 * statements do not exist yet, and on a pre-v2 file the meta table may
 * not either — a prepare failure is "no version"). */
static int read_schema_version(sqlite3 *conn, int64_t *ver_out) {
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(conn, "SELECT value FROM meta WHERE key = 'schema_version'",
                           -1, &s, NULL) != SQLITE_OK) {
        return -1;
    }
    int rc = -1;
    if (sqlite3_step(s) == SQLITE_ROW && sqlite3_column_type(s, 0) == SQLITE_INTEGER) {
        *ver_out = sqlite3_column_int64(s, 0);
        rc = 0;
    }
    sqlite3_finalize(s);
    return rc;
}

static int count_tables(sqlite3 *conn, int64_t *n_out) {
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(conn, "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'",
                           -1, &s, NULL) != SQLITE_OK) {
        return -1;
    }
    int rc = -1;
    if (sqlite3_step(s) == SQLITE_ROW) {
        *n_out = sqlite3_column_int64(s, 0);
        rc = 0;
    }
    sqlite3_finalize(s);
    return rc;
}

/* Brings the schema to v2: a matching version is left as it is; anything
 * else is dropped and recreated with its version, in one transaction. */
static int ensure_schema(sqlite3 *conn) {
    int64_t ver = 0;
    char *err = NULL;

    if (read_schema_version(conn, &ver) == 0 && ver == EXP_DB_SCHEMA_VERSION) {
        if (sqlite3_exec(conn, SCHEMA_SQL, NULL, NULL, &err) != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG, "schema exec failed: %s", err ? err : "?");
            sqlite3_free(err);
            return -1;
        }
        return 0;
    }

    int64_t n_tables = 0;
    if (count_tables(conn, &n_tables) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "cannot read sqlite_master: %s", sqlite3_errmsg(conn));
        return -1;
    }
    if (n_tables > 0) {
        QGP_LOG_WARN(LOG_TAG, "index schema is not v%d — dropping it; the index is rebuilt from height 1",
                     EXP_DB_SCHEMA_VERSION);
    }

    if (sqlite3_exec(conn, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "schema BEGIN failed: %s", err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    char set_ver[96];
    snprintf(set_ver, sizeof(set_ver),
             "INSERT INTO meta(key, value) VALUES('schema_version', %d)", EXP_DB_SCHEMA_VERSION);
    if (sqlite3_exec(conn, DROP_ALL_SQL, NULL, NULL, &err) != SQLITE_OK ||
        sqlite3_exec(conn, SCHEMA_SQL, NULL, NULL, &err) != SQLITE_OK ||
        sqlite3_exec(conn, set_ver, NULL, NULL, &err) != SQLITE_OK ||
        sqlite3_exec(conn, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "schema v%d create failed: %s", EXP_DB_SCHEMA_VERSION, err ? err : "?");
        sqlite3_free(err);
        sqlite3_exec(conn, "ROLLBACK", NULL, NULL, NULL);
        return -1;
    }
    return 0;
}

int exp_db_open(const char *path, exp_db_t **db_out) {
    if (!path || !db_out) return -1;
    *db_out = NULL;

    exp_db_t *db = calloc(1, sizeof(*db));
    if (!db) return -1;

    /* FULLMUTEX: the sync thread (writer) and the HTTP thread (reader)
     * share this one sqlite3* handle; FULLMUTEX serializes their calls
     * into libsqlite3. A reader on the same connection WOULD see an
     * uncommitted height mid-write — the sync thread therefore holds the
     * caller's db_lock as a writer around each exp_db_write_height
     * (exp_sync.c), and the HTTP thread reads under the reader side. */
    if (sqlite3_open_v2(path, &db->conn,
                         SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                         NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "open(%s) failed: %s", path, db->conn ? sqlite3_errmsg(db->conn) : "?");
        if (db->conn) sqlite3_close(db->conn);
        free(db);
        return -1;
    }

    sqlite3_exec(db->conn, "PRAGMA busy_timeout=5000", NULL, NULL, NULL);
    /* WAL mode (ignored on ":memory:"). */
    sqlite3_exec(db->conn, "PRAGMA journal_mode=WAL", NULL, NULL, NULL);

    if (ensure_schema(db->conn) != 0) {
        sqlite3_close(db->conn);
        free(db);
        return -1;
    }

    if (sqlite3_prepare_v2(db->conn, INSERT_BLOCK_SQL, -1, &db->stmt_insert_block, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, INSERT_ITEM_SQL, -1, &db->stmt_insert_item, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, INSERT_RECORD_SQL, -1, &db->stmt_insert_record, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, INSERT_IO_SQL, -1, &db->stmt_insert_io, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, INSERT_NAME_SQL, -1, &db->stmt_insert_name, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, RESOLVE_COIN_SQL, -1, &db->stmt_resolve_coin, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, GET_META_SQL, -1, &db->stmt_get_meta, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, SET_META_SQL, -1, &db->stmt_set_meta, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, QUERY_BLOCKS_SQL, -1, &db->stmt_query_blocks, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, QUERY_BLOCK_BY_HEIGHT_SQL, -1, &db->stmt_query_block_by_height, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, QUERY_BLOCK_BY_ID_SQL, -1, &db->stmt_query_block_by_id, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, QUERY_ITEMS_SQL, -1, &db->stmt_query_items, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, QUERY_ITEM_SQL, -1, &db->stmt_query_item, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, QUERY_ITEM_BY_ID_SQL, -1, &db->stmt_query_item_by_id, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, QUERY_ITEM_BY_NAME_SQL, -1, &db->stmt_query_item_by_name, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, QUERY_IOS_SQL, -1, &db->stmt_query_ios, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db->conn, QUERY_ADDRESS_SQL, -1, &db->stmt_query_address, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "prepare failed: %s", sqlite3_errmsg(db->conn));
        exp_db_close(db);
        return -1;
    }

    *db_out = db;
    return 0;
}

void exp_db_close(exp_db_t *db) {
    if (!db) return;

    sqlite3_stmt *stmts[] = {
        db->stmt_insert_block, db->stmt_insert_item, db->stmt_insert_record,
        db->stmt_insert_io, db->stmt_insert_name, db->stmt_resolve_coin,
        db->stmt_get_meta, db->stmt_set_meta,
        db->stmt_query_blocks, db->stmt_query_block_by_height, db->stmt_query_block_by_id,
        db->stmt_query_items, db->stmt_query_item, db->stmt_query_item_by_id,
        db->stmt_query_item_by_name, db->stmt_query_ios, db->stmt_query_address,
    };
    for (size_t i = 0; i < sizeof(stmts) / sizeof(stmts[0]); i++) {
        if (stmts[i]) sqlite3_finalize(stmts[i]);
    }

    if (db->conn) sqlite3_close(db->conn);
    free(db);
}

/* ── Write one height ───────────────────────────────────────────────── */

/* Structural checks before any write: header present, items exactly
 * 0..n-1 of this height, io rows of applied items of this batch in
 * (idx, dir, pos) ascending order — the order write_height inserts them,
 * which is what makes a same-block consumption resolve against a creation
 * at a lower index. */
static int batch_valid(const exp_block_batch_t *b) {
    if (!b->have_header) return 0;
    if (b->block.height == 0) return 0;
    if (b->n_items != (size_t)b->block.n_items) return 0;
    if (b->n_items > 0 && !b->items) return 0;
    if (b->n_ios > 0 && !b->ios) return 0;

    for (size_t i = 0; i < b->n_items; i++) {
        const exp_item_row_t *it = &b->items[i];
        if (it->height != b->block.height || it->idx != (uint32_t)i) return 0;
        if (!it->has_effects && (it->rec.kind != 0 || it->burned != 0)) return 0;
        /* HF-4: a name only on an applied item, with a price; a price only
         * with a name (exp_extract item_ok checks the name's bytes) */
        if (memchr(it->name, '\0', sizeof(it->name)) == NULL) return 0;
        if (it->name[0] && (!it->has_effects || it->code != 0 || it->name_price == 0)) return 0;
        if (!it->name[0] && it->name_price != 0) return 0;
    }
    for (size_t k = 0; k < b->n_ios; k++) {
        const exp_io_row_t *io = &b->ios[k];
        if (io->height != b->block.height || io->idx >= b->n_items) return 0;
        if (io->dir != 0 && io->dir != 1) return 0;
        if (!b->items[io->idx].has_effects) return 0;
        if (io->dir == 1 && !io->has_owner) return 0;
        if (k > 0) {
            const exp_io_row_t *p = &b->ios[k - 1];
            int ordered = (io->idx > p->idx) ||
                          (io->idx == p->idx && io->dir > p->dir) ||
                          (io->idx == p->idx && io->dir == p->dir && io->pos > p->pos);
            if (!ordered) return 0;
        }
    }
    return 1;
}

static int step_done(exp_db_t *db, sqlite3_stmt *s, const char *what) {
    int rc = sqlite3_step(s);
    sqlite3_reset(s);
    if (rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "%s failed: %s", what, sqlite3_errmsg(db->conn));
        return -1;
    }
    return 0;
}

static void bind_text_or_null(sqlite3_stmt *s, int col, const char *v) {
    if (v && v[0]) sqlite3_bind_text(s, col, v, -1, SQLITE_STATIC);
    else sqlite3_bind_null(s, col);
}

static int insert_item(exp_db_t *db, const exp_item_row_t *it) {
    sqlite3_stmt *s = db->stmt_insert_item;
    sqlite3_reset(s);
    sqlite3_bind_int64(s, 1, (sqlite3_int64)it->height);
    sqlite3_bind_int64(s, 2, (sqlite3_int64)it->idx);
    sqlite3_bind_int(s, 3, it->kind);
    sqlite3_bind_int64(s, 4, (sqlite3_int64)it->code);
    if (it->has_wire_id) sqlite3_bind_blob(s, 5, it->wire_id, 64, SQLITE_STATIC);
    else sqlite3_bind_null(s, 5);
    if (it->has_intent_id) sqlite3_bind_blob(s, 6, it->intent_id, 64, SQLITE_STATIC);
    else sqlite3_bind_null(s, 6);
    if (it->has_fee) sqlite3_bind_int64(s, 7, (sqlite3_int64)it->fee);
    else sqlite3_bind_null(s, 7);
    bind_text_or_null(s, 8, it->op);
    sqlite3_bind_int(s, 9, it->has_effects ? 1 : 0);
    sqlite3_bind_int64(s, 10, (sqlite3_int64)it->burned);
    if (step_done(db, s, "insert item") != 0) return -1;

    if (it->rec.kind == 0) return 0;

    const exp_record_row_t *r = &it->rec;
    s = db->stmt_insert_record;
    sqlite3_reset(s);
    sqlite3_bind_int64(s, 1, (sqlite3_int64)it->height);
    sqlite3_bind_int64(s, 2, (sqlite3_int64)it->idx);
    sqlite3_bind_int(s, 3, r->kind);
    bind_text_or_null(s, 4, r->validator);
    bind_text_or_null(s, 5, r->delegator);
    bind_text_or_null(s, 6, r->dest);
    sqlite3_bind_int64(s, 7, (sqlite3_int64)r->amount);
    sqlite3_bind_int64(s, 8, (sqlite3_int64)r->commission_bps);
    sqlite3_bind_int64(s, 9, (sqlite3_int64)r->param_id);
    sqlite3_bind_int64(s, 10, (sqlite3_int64)r->new_value);
    sqlite3_bind_int64(s, 11, (sqlite3_int64)r->effective);
    return step_done(db, s, "insert record");
}

/* A consumed row takes its owner/token/amount from the coin's creating
 * row when the index holds it; NULL columns otherwise (exp_db.h). */
static int insert_io(exp_db_t *db, const exp_io_row_t *io) {
    char     address[129];
    uint8_t  token[64];
    uint64_t amount = 0;
    int      has_owner = 0;

    if (io->dir == 1) {
        memcpy(address, io->address, sizeof(address));
        address[128] = '\0';
        memcpy(token, io->token_id, 64);
        amount = io->amount;
        has_owner = 1;
    } else {
        sqlite3_stmt *r = db->stmt_resolve_coin;
        sqlite3_reset(r);
        sqlite3_bind_blob(r, 1, io->coin_id, 64, SQLITE_STATIC);
        int rc = sqlite3_step(r);
        if (rc == SQLITE_ROW) {
            const unsigned char *a = sqlite3_column_text(r, 0);
            const void *t = sqlite3_column_blob(r, 1);
            if (a && t && sqlite3_column_bytes(r, 1) == 64) {
                strncpy(address, (const char *)a, 128);
                address[128] = '\0';
                memcpy(token, t, 64);
                amount = (uint64_t)sqlite3_column_int64(r, 2);
                has_owner = 1;
            }
        } else if (rc != SQLITE_DONE) {
            QGP_LOG_ERROR(LOG_TAG, "resolve coin failed: %s", sqlite3_errmsg(db->conn));
            sqlite3_reset(r);
            return -1;
        }
        sqlite3_reset(r);
    }

    sqlite3_stmt *s = db->stmt_insert_io;
    sqlite3_reset(s);
    sqlite3_bind_int64(s, 1, (sqlite3_int64)io->height);
    sqlite3_bind_int64(s, 2, (sqlite3_int64)io->idx);
    sqlite3_bind_int(s, 3, io->dir);
    sqlite3_bind_int64(s, 4, (sqlite3_int64)io->pos);
    sqlite3_bind_blob(s, 5, io->coin_id, 64, SQLITE_STATIC);
    if (has_owner) {
        sqlite3_bind_text(s, 6, address, -1, SQLITE_TRANSIENT);
        sqlite3_bind_blob(s, 7, token, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(s, 8, (sqlite3_int64)amount);
    } else {
        sqlite3_bind_null(s, 6);
        sqlite3_bind_null(s, 7);
        sqlite3_bind_null(s, 8);
    }
    sqlite3_bind_int64(s, 9, (sqlite3_int64)(io->dir == 1 ? io->unlock_block : 0));
    return step_done(db, s, "insert item_io");
}

/* HF-4: the item_names row of a registration, after the item's io rows
 * (its owner is read from the first consumed one, INSERT_NAME_SQL). */
static int insert_name(exp_db_t *db, const exp_item_row_t *it) {
    sqlite3_stmt *s = db->stmt_insert_name;
    sqlite3_reset(s);
    sqlite3_bind_int64(s, 1, (sqlite3_int64)it->height);
    sqlite3_bind_int64(s, 2, (sqlite3_int64)it->idx);
    sqlite3_bind_text(s, 3, it->name, -1, SQLITE_STATIC);
    sqlite3_bind_int64(s, 4, (sqlite3_int64)it->name_price);
    return step_done(db, s, "insert item_names");
}

int exp_db_write_height(exp_db_t *db, const exp_block_batch_t *b) {
    if (!db || !db->conn || !b) return -1;
    if (!batch_valid(b)) {
        QGP_LOG_ERROR(LOG_TAG, "write_height: malformed batch for height %llu",
                      (unsigned long long)b->block.height);
        return -1;
    }

    char *err = NULL;
    if (sqlite3_exec(db->conn, "BEGIN IMMEDIATE", NULL, NULL, &err) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "write_height: BEGIN failed: %s", err ? err : "?");
        sqlite3_free(err);
        return -1;
    }

    /* Read the watermark INSIDE the transaction — the order check and the
     * write are one atomic step. */
    uint64_t last = 0;
    int have_last = (exp_db_get_meta_u64(db, "last_indexed_height", &last) == 0);
    uint64_t expected = have_last ? last + 1 : 1;
    if (b->block.height != expected) {
        QGP_LOG_ERROR(LOG_TAG, "write_height: height %llu is not the next height (%llu)",
                      (unsigned long long)b->block.height, (unsigned long long)expected);
        sqlite3_exec(db->conn, "ROLLBACK", NULL, NULL, NULL);
        return -1;
    }

    const exp_block_row_t *bl = &b->block;
    sqlite3_stmt *s = db->stmt_insert_block;
    sqlite3_reset(s);
    sqlite3_bind_int64(s, 1, (sqlite3_int64)bl->height);
    sqlite3_bind_blob(s, 2, bl->block_id, 64, SQLITE_STATIC);
    sqlite3_bind_blob(s, 3, bl->prev_id, 64, SQLITE_STATIC);
    sqlite3_bind_int64(s, 4, (sqlite3_int64)bl->time_ms);
    sqlite3_bind_blob(s, 5, bl->proposer,
                      (int)(bl->proposer_len <= 64 ? bl->proposer_len : 64), SQLITE_STATIC);
    sqlite3_bind_blob(s, 6, bl->global_root, 64, SQLITE_STATIC);
    sqlite3_bind_int64(s, 7, (sqlite3_int64)bl->applied_count);
    sqlite3_bind_int64(s, 8, (sqlite3_int64)bl->n_items);
    if (step_done(db, s, "insert block") != 0) goto fail;

    /* Items, then each item's io rows in batch order (grouped by item,
     * consumed before created) — so a consumption in item j resolves a
     * creation in item i < j of this same block. */
    size_t k = 0;
    for (size_t i = 0; i < b->n_items; i++) {
        if (insert_item(db, &b->items[i]) != 0) goto fail;
        while (k < b->n_ios && b->ios[k].idx == (uint32_t)i) {
            if (insert_io(db, &b->ios[k]) != 0) goto fail;
            k++;
        }
        if (b->items[i].name[0] && insert_name(db, &b->items[i]) != 0) goto fail;
    }
    if (k != b->n_ios) goto fail;   /* unreachable after batch_valid */

    if (exp_db_set_meta_u64(db, "last_indexed_height", bl->height) != 0) goto fail;

    if (sqlite3_exec(db->conn, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "write_height: COMMIT failed: %s", err ? err : "?");
        sqlite3_free(err);
        goto fail;
    }
    return 0;

fail:
    sqlite3_exec(db->conn, "ROLLBACK", NULL, NULL, NULL);
    QGP_LOG_ERROR(LOG_TAG, "write_height(%llu) rolled back", (unsigned long long)bl->height);
    return -1;
}

/* ── Meta ────────────────────────────────────────────────────────────── */

int exp_db_get_meta_u64(exp_db_t *db, const char *key, uint64_t *val_out) {
    if (!db || !db->conn || !key || !val_out) return -1;

    sqlite3_stmt *s = db->stmt_get_meta;
    sqlite3_reset(s);
    sqlite3_bind_text(s, 1, key, -1, SQLITE_STATIC);

    int rc = -1;
    if (sqlite3_step(s) == SQLITE_ROW && sqlite3_column_type(s, 0) == SQLITE_INTEGER) {
        *val_out = (uint64_t)sqlite3_column_int64(s, 0);
        rc = 0;
    }
    sqlite3_reset(s);
    return rc;
}

int exp_db_set_meta_u64(exp_db_t *db, const char *key, uint64_t val) {
    if (!db || !db->conn || !key) return -1;

    sqlite3_stmt *s = db->stmt_set_meta;
    sqlite3_reset(s);
    sqlite3_bind_text(s, 1, key, -1, SQLITE_STATIC);
    sqlite3_bind_int64(s, 2, (sqlite3_int64)val);
    return step_done(db, s, "set_meta_u64");
}

int exp_db_get_meta_blob(exp_db_t *db, const char *key, uint8_t *buf, size_t buflen, size_t *len_out) {
    if (!db || !db->conn || !key || !buf || !len_out) return -1;

    sqlite3_stmt *s = db->stmt_get_meta;
    sqlite3_reset(s);
    sqlite3_bind_text(s, 1, key, -1, SQLITE_STATIC);

    int rc = -1;
    if (sqlite3_step(s) == SQLITE_ROW && sqlite3_column_type(s, 0) == SQLITE_BLOB) {
        const void *blob = sqlite3_column_blob(s, 0);
        int blob_len = sqlite3_column_bytes(s, 0);
        if (blob_len >= 0 && (size_t)blob_len <= buflen) {
            if (blob_len > 0 && blob) memcpy(buf, blob, (size_t)blob_len);
            *len_out = (size_t)blob_len;
            rc = 0;
        }
    }
    sqlite3_reset(s);
    return rc;
}

int exp_db_set_meta_blob(exp_db_t *db, const char *key, const uint8_t *buf, size_t len) {
    if (!db || !db->conn || !key || (!buf && len > 0)) return -1;

    sqlite3_stmt *s = db->stmt_set_meta;
    sqlite3_reset(s);
    sqlite3_bind_text(s, 1, key, -1, SQLITE_STATIC);
    sqlite3_bind_blob(s, 2, buf, (int)len, SQLITE_STATIC);
    return step_done(db, s, "set_meta_blob");
}

/* ── --verify-index ─────────────────────────────────────────────────── */

static int scalar_i64(exp_db_t *db, const char *sql, int64_t *out) {
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db->conn, sql, -1, &s, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "verify: prepare failed: %s", sqlite3_errmsg(db->conn));
        return -1;
    }
    int rc = -1;
    if (sqlite3_step(s) == SQLITE_ROW) {
        *out = sqlite3_column_int64(s, 0);
        rc = 0;
    }
    sqlite3_finalize(s);
    return rc;
}

int exp_db_verify_index(exp_db_t *db) {
    if (!db || !db->conn) return -1;

    uint64_t last = 0;
    if (exp_db_get_meta_u64(db, "last_indexed_height", &last) != 0) last = 0;

    int64_t n_blocks = 0, min_h = 0, max_h = 0;
    if (scalar_i64(db, "SELECT COUNT(*) FROM blocks", &n_blocks) != 0 ||
        scalar_i64(db, "SELECT IFNULL(MIN(height), 0) FROM blocks", &min_h) != 0 ||
        scalar_i64(db, "SELECT IFNULL(MAX(height), 0) FROM blocks", &max_h) != 0) {
        return -1;
    }
    /* height is the PRIMARY KEY (unique): count == max with min == 1
     * means exactly 1..max. */
    int heights_ok = (last == 0) ? (n_blocks == 0)
                                 : ((uint64_t)n_blocks == last && min_h == 1 && (uint64_t)max_h == last);
    if (!heights_ok) {
        QGP_LOG_ERROR(LOG_TAG, "verify: blocks are not exactly heights 1..%llu (count %lld, min %lld, max %lld)",
                      (unsigned long long)last, (long long)n_blocks, (long long)min_h, (long long)max_h);
        return -1;
    }

    /* applied_count is v2_blocks.tx_count: the count of items classified
     * ENVELOPE whose result is OK (nodus_witness_v2_apply.c phase 13,
     * "the ROW'S OWN RULE" loop over blk->n_envs; n_envs counts the items
     * nodus_witness_v2_classify_entry calls ENVELOPE,
     * nodus_witness_cmt_app.c FinalizeBlock) — and dnac_v3_block sets
     * kind 1 with that same classifier (nodus_witness_handlers.c v3b_item)
     * and code from the stored per-item result. So applied_count equals
     * the stored items with kind 1 AND code 0. */
    static const struct { const char *what; const char *sql; } checks[] = {
        { "block item count / applied_count",
          "SELECT COUNT(*) FROM blocks b WHERE "
          "b.n_items != (SELECT COUNT(*) FROM items i WHERE i.height = b.height) OR "
          "b.applied_count != (SELECT COUNT(*) FROM items i WHERE i.height = b.height "
          "                    AND i.kind = 1 AND i.code = 0)" },
        { "item without a block",
          "SELECT COUNT(*) FROM items i WHERE NOT EXISTS "
          "(SELECT 1 FROM blocks b WHERE b.height = i.height)" },
        { "io row without an applied item",
          "SELECT COUNT(*) FROM item_io o WHERE NOT EXISTS "
          "(SELECT 1 FROM items i WHERE i.height = o.height AND i.idx = o.idx "
          " AND i.code = 0 AND i.has_effects = 1)" },
        { "record without an applied item",
          "SELECT COUNT(*) FROM item_records r WHERE NOT EXISTS "
          "(SELECT 1 FROM items i WHERE i.height = r.height AND i.idx = r.idx "
          " AND i.code = 0 AND i.has_effects = 1)" },
        { "refused item with effects",
          "SELECT COUNT(*) FROM items WHERE code != 0 AND (has_effects != 0 OR burned != 0)" },
        { "name row without an applied item",
          "SELECT COUNT(*) FROM item_names n WHERE NOT EXISTS "
          "(SELECT 1 FROM items i WHERE i.height = n.height AND i.idx = n.idx "
          " AND i.code = 0 AND i.has_effects = 1)" },
        { "chain name registered twice",
          "SELECT COUNT(*) FROM (SELECT name FROM item_names GROUP BY name HAVING COUNT(*) > 1)" },
    };

    for (size_t c = 0; c < sizeof(checks) / sizeof(checks[0]); c++) {
        int64_t bad = 0;
        if (scalar_i64(db, checks[c].sql, &bad) != 0) return -1;
        if (bad != 0) {
            QGP_LOG_ERROR(LOG_TAG, "verify: %lld row(s) fail check '%s'", (long long)bad, checks[c].what);
            return -1;
        }
    }
    return 0;
}

/* ── Read side ───────────────────────────────────────────────────────── */

static sqlite3_int64 clamp_cursor(uint64_t v) {
    return (v > (uint64_t)INT64_MAX) ? (sqlite3_int64)INT64_MAX : (sqlite3_int64)v;
}

int exp_db_query_blocks(exp_db_t *db, uint64_t before_height, int limit,
                        exp_block_row_t *rows, int *count_out) {
    if (!db || !db->conn || !rows || !count_out || limit <= 0) return -1;

    sqlite3_stmt *s = db->stmt_query_blocks;
    sqlite3_reset(s);
    sqlite3_bind_int64(s, 1, clamp_cursor(before_height));
    sqlite3_bind_int(s, 2, limit);

    int n = 0, rc = 0;
    while (n < limit) {
        int st = sqlite3_step(s);
        if (st == SQLITE_DONE) break;
        if (st != SQLITE_ROW) {
            QGP_LOG_ERROR(LOG_TAG, "query_blocks step failed: %s", sqlite3_errmsg(db->conn));
            rc = -1;
            break;
        }
        row_to_block(s, &rows[n]);
        n++;
    }
    sqlite3_reset(s);
    *count_out = n;
    return rc;
}

static int query_one_block(sqlite3_stmt *s, exp_block_row_t *row_out) {
    int rc = -1;
    if (sqlite3_step(s) == SQLITE_ROW) {
        row_to_block(s, row_out);
        rc = 0;
    }
    sqlite3_reset(s);
    return rc;
}

int exp_db_query_block_by_height(exp_db_t *db, uint64_t height, exp_block_row_t *row_out) {
    if (!db || !db->conn || !row_out) return -1;
    sqlite3_stmt *s = db->stmt_query_block_by_height;
    sqlite3_reset(s);
    sqlite3_bind_int64(s, 1, clamp_cursor(height));
    return query_one_block(s, row_out);
}

int exp_db_query_block_by_id(exp_db_t *db, const uint8_t block_id[64], exp_block_row_t *row_out) {
    if (!db || !db->conn || !block_id || !row_out) return -1;
    sqlite3_stmt *s = db->stmt_query_block_by_id;
    sqlite3_reset(s);
    sqlite3_bind_blob(s, 1, block_id, 64, SQLITE_STATIC);
    return query_one_block(s, row_out);
}

static int query_items_list(exp_db_t *db, sqlite3_stmt *s, int max,
                            exp_item_row_t *rows, int *count_out, const char *what) {
    int n = 0, rc = 0;
    while (n < max) {
        int st = sqlite3_step(s);
        if (st == SQLITE_DONE) break;
        if (st != SQLITE_ROW) {
            QGP_LOG_ERROR(LOG_TAG, "%s step failed: %s", what, sqlite3_errmsg(db->conn));
            rc = -1;
            break;
        }
        row_to_item(s, &rows[n]);
        n++;
    }
    sqlite3_reset(s);
    *count_out = n;
    return rc;
}

int exp_db_query_items(exp_db_t *db, uint64_t height, uint32_t from_idx, int max,
                       exp_item_row_t *rows, int *count_out) {
    if (!db || !db->conn || !rows || !count_out || max <= 0) return -1;
    sqlite3_stmt *s = db->stmt_query_items;
    sqlite3_reset(s);
    sqlite3_bind_int64(s, 1, clamp_cursor(height));
    sqlite3_bind_int64(s, 2, (sqlite3_int64)from_idx);
    sqlite3_bind_int(s, 3, max);
    return query_items_list(db, s, max, rows, count_out, "query_items");
}

static int query_one_item(sqlite3_stmt *s, exp_item_row_t *row_out) {
    int rc = -1;
    if (sqlite3_step(s) == SQLITE_ROW) {
        row_to_item(s, row_out);
        rc = 0;
    }
    sqlite3_reset(s);
    return rc;
}

int exp_db_query_item(exp_db_t *db, uint64_t height, uint32_t idx, exp_item_row_t *row_out) {
    if (!db || !db->conn || !row_out) return -1;
    sqlite3_stmt *s = db->stmt_query_item;
    sqlite3_reset(s);
    sqlite3_bind_int64(s, 1, clamp_cursor(height));
    sqlite3_bind_int64(s, 2, (sqlite3_int64)idx);
    return query_one_item(s, row_out);
}

int exp_db_query_item_by_id(exp_db_t *db, const uint8_t id[64], exp_item_row_t *row_out) {
    if (!db || !db->conn || !id || !row_out) return -1;
    sqlite3_stmt *s = db->stmt_query_item_by_id;
    sqlite3_reset(s);
    sqlite3_bind_blob(s, 1, id, 64, SQLITE_STATIC);
    return query_one_item(s, row_out);
}

int exp_db_query_item_by_name(exp_db_t *db, const char *name, exp_item_row_t *row_out) {
    if (!db || !db->conn || !name || !row_out) return -1;
    sqlite3_stmt *s = db->stmt_query_item_by_name;
    sqlite3_reset(s);
    sqlite3_bind_text(s, 1, name, -1, SQLITE_STATIC);
    return query_one_item(s, row_out);
}

int exp_db_query_item_ios(exp_db_t *db, uint64_t height, uint32_t idx,
                          exp_io_row_t *rows, int max, int *count_out) {
    if (!db || !db->conn || !rows || !count_out || max <= 0) return -1;
    sqlite3_stmt *s = db->stmt_query_ios;
    sqlite3_reset(s);
    sqlite3_bind_int64(s, 1, clamp_cursor(height));
    sqlite3_bind_int64(s, 2, (sqlite3_int64)idx);
    sqlite3_bind_int(s, 3, max);

    int n = 0, rc = 0;
    while (n < max) {
        int st = sqlite3_step(s);
        if (st == SQLITE_DONE) break;
        if (st != SQLITE_ROW) {
            QGP_LOG_ERROR(LOG_TAG, "query_item_ios step failed: %s", sqlite3_errmsg(db->conn));
            rc = -1;
            break;
        }
        row_to_io(s, &rows[n]);
        n++;
    }
    sqlite3_reset(s);
    *count_out = n;
    return rc;
}

int exp_db_query_address(exp_db_t *db, const char *fp,
                         uint64_t before_height, uint32_t before_idx, int limit,
                         exp_item_row_t *rows, int *count_out) {
    if (!db || !db->conn || !fp || !rows || !count_out || limit <= 0) return -1;
    sqlite3_stmt *s = db->stmt_query_address;
    sqlite3_reset(s);
    sqlite3_bind_text(s, 1, fp, -1, SQLITE_STATIC);
    sqlite3_bind_int64(s, 2, clamp_cursor(before_height));
    sqlite3_bind_int64(s, 3, (sqlite3_int64)before_idx);
    sqlite3_bind_int(s, 4, limit);
    return query_items_list(db, s, limit, rows, count_out, "query_address");
}
