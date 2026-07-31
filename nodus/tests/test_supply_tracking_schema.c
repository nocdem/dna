/**
 * Nodus — supply_tracking open-time schema test (K4)
 *
 * supply_tracking used to be created ONLY by nodus_witness_supply_init
 * (nodus_witness_db.c:879-888), which runs at genesis commit. A node
 * that created its chain DB and then joined the cluster before replaying
 * genesis therefore had NO supply_tracking table at all, and every
 * supply read/write against it silently no-op'd (supply_add_minted
 * treats a failed prepare as an advisory no-op,
 * nodus_witness_db.c:950-954).
 *
 * The table is now part of WITNESS_DB_SCHEMA, so it exists from the
 * moment the chain DB is opened. It must exist EMPTY: an absent id=1
 * row is the correct pre-genesis state, and supply_get reports
 * "not initialised" from the missing row (nodus_witness_db.c:925-928).
 * A pre-seeded row would make supply_init's "already initialized"
 * probe (nodus_witness_db.c:872) refuse the real genesis supply.
 *
 * Runs against the real nodus_witness_create_chain_db path so
 * WITNESS_DB_SCHEMA + the migrations are exercised end to end — same
 * approach as tests/test_stake_schema.c.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CHECK_EQ(a, b) do { \
    long long _a = (long long)(a), _b = (long long)(b); \
    if (_a != _b) { \
        fprintf(stderr, "CHECK_EQ fail at %s:%d: %lld != %lld\n", \
                __FILE__, __LINE__, _a, _b); \
        exit(1); \
    } } while (0)

#define CHECK_TRUE(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK_TRUE fail at %s:%d: %s\n", \
                __FILE__, __LINE__, #cond); \
        exit(1); \
    } } while (0)

static int sqlite_master_count(sqlite3 *db, const char *type,
                               const char *name) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM sqlite_master WHERE type=? AND name=?",
            -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, type, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, name, -1, SQLITE_STATIC);
    int count = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}

static int table_has_column(sqlite3 *db, const char *table, const char *col) {
    char sql[256];
    snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    int found = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(stmt, 1);
        if (name && strcmp((const char *)name, col) == 0) { found = 1; break; }
    }
    sqlite3_finalize(stmt);
    return found;
}

static int table_row_count(sqlite3 *db, const char *table) {
    char sql[256];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s", table);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    int n = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) n = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return n;
}

static void rmrf(const char *path) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    int rc = system(cmd);
    (void)rc;
}

/* ── Legacy DB: supply_tracking WITHOUT total_minted ────────────────
 *
 * The shape the round-3 review flagged: a DB that already holds the
 * id = 1 row but predates the total_minted column. supply_init used to
 * return -2 ("already initialized") several statements BEFORE its own
 * ALTER, so that DB could never gain the column — and under the merged
 * D1/D2/D3 fail-close chain a missing column now makes supply_get return
 * a hard -1, which fails the epoch_state leaf load, which fails
 * compute_state_root, which rejects every block.
 *
 * Nobody proved such a DB still exists (the chain was wiped) — these are
 * guard tests, not the reproduction of an observed incident.
 *
 * The fixture must also carry the three tables migrate_v12 ALTERs
 * unconditionally (committed_transactions / blocks / utxo_set): that
 * function abort()s on any sqlite error other than "duplicate column
 * name", so an absent table there would kill the process. Mirrors
 * setup_pre_v12 in tests/test_schema_migration.c. */
static int legacy_db_open(nodus_witness_t *w) {
    if (sqlite3_open(":memory:", &w->db) != SQLITE_OK) return -1;

    const char *schema =
        "CREATE TABLE committed_transactions ("
        "  tx_hash BLOB PRIMARY KEY,"
        "  tx_type INTEGER NOT NULL,"
        "  tx_data BLOB NOT NULL,"
        "  tx_len  INTEGER NOT NULL,"
        "  block_height INTEGER NOT NULL DEFAULT 0"
        ");"
        "CREATE TABLE blocks ("
        "  height INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  tx_root BLOB NOT NULL,"
        "  timestamp INTEGER NOT NULL,"
        "  state_root BLOB NOT NULL"
        ");"
        "CREATE TABLE utxo_set ("
        "  nullifier BLOB PRIMARY KEY,"
        "  owner TEXT NOT NULL,"
        "  amount INTEGER NOT NULL,"
        "  token_id BLOB NOT NULL,"
        "  tx_hash BLOB NOT NULL,"
        "  output_index INTEGER NOT NULL"
        ");"
        /* The legacy shape: SIX columns, no total_minted. */
        "CREATE TABLE supply_tracking ("
        "  id INTEGER PRIMARY KEY CHECK(id = 1),"
        "  genesis_supply INTEGER NOT NULL,"
        "  total_burned INTEGER NOT NULL DEFAULT 0,"
        "  current_supply INTEGER NOT NULL,"
        "  last_tx_hash BLOB NOT NULL,"
        "  last_sequence INTEGER NOT NULL"
        ");"
        "INSERT INTO supply_tracking (id, genesis_supply, total_burned,"
        " current_supply, last_tx_hash, last_sequence)"
        " VALUES (1, 5000, 0, 5000, x'00', 1);";

    char *err = NULL;
    if (sqlite3_exec(w->db, schema, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "legacy schema failed: %s\n", err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

/* migrate_v12 runs on EVERY chain-DB open, so this is the leg that
 * repairs a legacy DB on a plain restart. */
static void test_legacy_db_gains_total_minted(void) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    CHECK_TRUE(w != NULL);
    CHECK_EQ(legacy_db_open(w), 0);

    /* Pre-state: the column is absent and supply_get is hard-broken —
     * the prepare fails on "no such column: total_minted", which the
     * three-valued contract reports as -1 (real error), NOT 1 (absent
     * row). That -1 is what rejects every block. */
    CHECK_TRUE(!table_has_column(w->db, "supply_tracking", "total_minted"));
    nodus_witness_supply_t sup;
    memset(&sup, 0, sizeof(sup));
    CHECK_EQ(nodus_witness_supply_get(w, &sup), -1);

    CHECK_EQ(nodus_witness_db_migrate_v12(w), 0);

    CHECK_TRUE(table_has_column(w->db, "supply_tracking", "total_minted"));
    CHECK_EQ(nodus_witness_supply_get(w, &sup), 0);
    CHECK_EQ(sup.genesis_supply, 5000);
    CHECK_EQ(sup.current_supply, 5000);
    CHECK_EQ(sup.total_minted, 0);       /* DEFAULT 0 back-filled */
    CHECK_EQ(sup.total_burned, 0);

    /* Idempotent: a second open must not fail or duplicate anything. */
    CHECK_EQ(nodus_witness_db_migrate_v12(w), 0);
    CHECK_EQ(nodus_witness_supply_get(w, &sup), 0);
    CHECK_EQ(sup.genesis_supply, 5000);

    sqlite3_close(w->db);
    free(w);
}

/* The other leg: supply_init's own migration is now reachable even when
 * it is about to return -2, because the schema statements moved ABOVE
 * the "already initialized" probe. */
static void test_supply_init_migrates_legacy_db(void) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    CHECK_TRUE(w != NULL);
    CHECK_EQ(legacy_db_open(w), 0);
    CHECK_TRUE(!table_has_column(w->db, "supply_tracking", "total_minted"));

    uint8_t genesis_tx_hash[NODUS_T3_TX_HASH_LEN];
    memset(genesis_tx_hash, 0x22, sizeof(genesis_tx_hash));

    /* Still -2 — the row exists, so re-initialising is still refused… */
    CHECK_EQ(nodus_witness_supply_init(w, 9999, genesis_tx_hash), -2);
    /* …but the column got added on the way there, and the existing row
     * is untouched (genesis_supply is still the legacy 5000, not 9999). */
    CHECK_TRUE(table_has_column(w->db, "supply_tracking", "total_minted"));
    CHECK_EQ(table_row_count(w->db, "supply_tracking"), 1);

    nodus_witness_supply_t sup;
    memset(&sup, 0, sizeof(sup));
    CHECK_EQ(nodus_witness_supply_get(w, &sup), 0);
    CHECK_EQ(sup.genesis_supply, 5000);
    CHECK_EQ(sup.total_minted, 0);

    sqlite3_close(w->db);
    free(w);
}

int main(void) {
    char data_path[] = "/tmp/test_supply_tracking_schema_XXXXXX";
    if (!mkdtemp(data_path)) {
        fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
        return 1;
    }

    /* nodus_witness_t is multi-MB — heap-allocate the fixture. */
    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) { fprintf(stderr, "calloc failed\n"); rmrf(data_path); return 1; }
    snprintf(w->data_path, sizeof(w->data_path), "%s", data_path);

    uint8_t chain_id[16];
    memset(chain_id, 0xC4, sizeof(chain_id));

    /* ── Fresh chain DB, genesis NOT replayed ───────────────────── */
    CHECK_EQ(nodus_witness_create_chain_db(w, chain_id), 0);
    CHECK_TRUE(w->db != NULL);

    /* K4: the table exists at open time, before any genesis commit. */
    CHECK_EQ(sqlite_master_count(w->db, "table", "supply_tracking"), 1);

    /* Column-for-column the supply_init definition, including the
     * total_minted column the pre-v0.16 migration back-fills. */
    CHECK_TRUE(table_has_column(w->db, "supply_tracking", "id"));
    CHECK_TRUE(table_has_column(w->db, "supply_tracking", "genesis_supply"));
    CHECK_TRUE(table_has_column(w->db, "supply_tracking", "total_burned"));
    CHECK_TRUE(table_has_column(w->db, "supply_tracking", "total_minted"));
    CHECK_TRUE(table_has_column(w->db, "supply_tracking", "current_supply"));
    CHECK_TRUE(table_has_column(w->db, "supply_tracking", "last_tx_hash"));
    CHECK_TRUE(table_has_column(w->db, "supply_tracking", "last_sequence"));

    /* Empty: no row is seeded — absent row IS the pre-genesis state. */
    CHECK_EQ(table_row_count(w->db, "supply_tracking"), 0);

    /* supply_get must therefore still report "not initialised" — and
     * under the three-valued contract merged alongside this change
     * (nodus_witness_db.h) that is EXACTLY 1 ("row genuinely absent"),
     * never -1 ("real error"). The distinction is load-bearing: the
     * epoch_state leaf loader zeroes the supply counters on 1 and fails
     * closed on -1. */
    nodus_witness_supply_t supply;
    memset(&supply, 0, sizeof(supply));
    CHECK_EQ(nodus_witness_supply_get(w, &supply), 1);

    /* The CHECK(id = 1) constraint survived into the open-time copy. */
    CHECK_TRUE(sqlite3_exec(w->db,
        "INSERT INTO supply_tracking (id, genesis_supply, total_burned,"
        " total_minted, current_supply, last_tx_hash, last_sequence)"
        " VALUES (2, 0, 0, 0, 0, x'00', 1)",
        NULL, NULL, NULL) != SQLITE_OK);
    CHECK_EQ(table_row_count(w->db, "supply_tracking"), 0);

    /* ── supply_init still works on top of the open-time table ──── */
    uint8_t genesis_tx_hash[NODUS_T3_TX_HASH_LEN];
    memset(genesis_tx_hash, 0x11, sizeof(genesis_tx_hash));
    CHECK_EQ(nodus_witness_supply_init(w, 1000, genesis_tx_hash), 0);
    CHECK_EQ(table_row_count(w->db, "supply_tracking"), 1);
    CHECK_EQ(nodus_witness_supply_get(w, &supply), 0);
    CHECK_EQ(supply.genesis_supply, 1000);
    CHECK_EQ(supply.current_supply, 1000);
    CHECK_EQ(supply.total_minted, 0);
    CHECK_EQ(supply.total_burned, 0);

    /* Second call sees the row and refuses to re-initialise. */
    CHECK_EQ(nodus_witness_supply_init(w, 2000, genesis_tx_hash), -2);

    /* ── Idempotence: reopen re-runs the schema, row survives ───── */
    sqlite3_close(w->db);
    w->db = NULL;
    CHECK_EQ(nodus_witness_create_chain_db(w, chain_id), 0);
    CHECK_EQ(sqlite_master_count(w->db, "table", "supply_tracking"), 1);
    CHECK_EQ(table_row_count(w->db, "supply_tracking"), 1);
    CHECK_EQ(nodus_witness_supply_get(w, &supply), 0);
    CHECK_EQ(supply.genesis_supply, 1000);

    sqlite3_close(w->db);
    w->db = NULL;
    free(w);
    rmrf(data_path);

    test_legacy_db_gains_total_minted();
    test_supply_init_migrates_legacy_db();

    printf("test_supply_tracking_schema: ALL CHECKS PASSED\n");
    return 0;
}
