/**
 * Nodus — Witness Auto-Bootstrap State Machine Tests (PR 3 Yol B)
 *
 * Verifies the bootstrap state machine transitions correctly for the
 * HAVE_CHAIN branch: a witness whose DB already contains a genesis
 * block (block_height >= 1) MUST move from INIT to DONE without any
 * network I/O, and MUST set bootstrap_settle_until_ms in the future
 * so the H-4 mid-round-disrupt mitigation engages.
 *
 * Subsequent commits (C3+) add coverage for the DISCOVER branch, the
 * cold-DR --cold-bootstrap escape, and FETCH_GENESIS atomicity.
 *
 * RED state for C2: the C1 stub returns 0 without changing state, so
 * post-call bootstrap_state stays at INIT (0). The asserts below fail
 * until C2-GREEN implements the HAVE_CHAIN branch.
 */

#include "witness/nodus_witness_bootstrap.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness.h"
#include "server/nodus_server.h"
#include "dnac/dnac.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sqlite3.h>

#define TEST(name) do { printf("  %-58s", name); fflush(stdout); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

/* Minimal pre-v12 schema mirroring test_schema_migration.c — enough
 * for migrate_v12 to add its v13/v14/v15/v16 sub-migrations on top. */
static int setup_schema(sqlite3 **db_out) {
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return -1;

    static const char *schema =
        "CREATE TABLE committed_transactions ("
        "  tx_hash BLOB PRIMARY KEY,"
        "  tx_type INTEGER NOT NULL,"
        "  tx_data BLOB NOT NULL,"
        "  tx_len  INTEGER NOT NULL,"
        "  block_height INTEGER NOT NULL DEFAULT 0,"
        "  timestamp INTEGER NOT NULL DEFAULT 0,"
        "  sender_fp TEXT,"
        "  fee INTEGER NOT NULL DEFAULT 0"
        ");"
        "CREATE INDEX idx_ctx_height ON committed_transactions(block_height);"
        "CREATE TABLE blocks ("
        "  height INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  tx_root BLOB NOT NULL,"
        "  tx_count INTEGER NOT NULL DEFAULT 1,"
        "  timestamp INTEGER NOT NULL,"
        "  proposer_id BLOB,"
        "  prev_hash BLOB NOT NULL DEFAULT x'',"
        "  state_root BLOB NOT NULL,"
        "  created_at INTEGER NOT NULL DEFAULT 0"
        ");"
        "CREATE TABLE utxo_set ("
        "  nullifier BLOB PRIMARY KEY,"
        "  owner TEXT NOT NULL,"
        "  amount INTEGER NOT NULL,"
        "  token_id BLOB NOT NULL,"
        "  tx_hash BLOB NOT NULL,"
        "  output_index INTEGER NOT NULL,"
        "  block_height INTEGER NOT NULL DEFAULT 0,"
        "  created_at INTEGER NOT NULL DEFAULT 0"
        ");";

    char *err = NULL;
    if (sqlite3_exec(db, schema, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "schema setup failed: %s\n", err ? err : "(null)");
        if (err) sqlite3_free(err);
        sqlite3_close(db);
        return -1;
    }
    *db_out = db;
    return 0;
}

/* Insert a stub block 1 row so the chain-DB-present check sees a
 * genesis block. The exact tx_root / state_root contents are
 * irrelevant for the bootstrap branch decision — only the row's
 * existence matters. */
static int insert_stub_block_1(sqlite3 *db) {
    static const uint8_t zeros64[64] = {0};
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
        "INSERT INTO blocks (height, tx_root, tx_count, timestamp, "
        "                     proposer_id, prev_hash, state_root, created_at) "
        "VALUES (1, ?, 0, 0, NULL, x'', ?, 0)",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_blob(stmt, 1, zeros64, sizeof(zeros64), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, zeros64, sizeof(zeros64), SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

static uint64_t now_monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static void test_have_chain_branch_reaches_done(void) {
    TEST("HAVE_CHAIN branch reaches DONE without network I/O");

    sqlite3 *db = NULL;
    if (setup_schema(&db) != 0) { FAIL("schema setup"); return; }

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    w.db = db;

    if (nodus_witness_db_migrate_v12(&w) != 0) {
        FAIL("migrate_v12");
        sqlite3_close(db);
        return;
    }

    if (insert_stub_block_1(db) != 0) {
        FAIL("seed block 1");
        sqlite3_close(db);
        return;
    }

    int rc = nodus_witness_bootstrap_start(&w);
    if (rc != 0) {
        FAIL("bootstrap_start returned non-zero");
        sqlite3_close(db);
        return;
    }
    if (w.bootstrap_state != (int)NODUS_W_BOOTSTRAP_DONE) {
        FAIL("expected state=DONE after HAVE_CHAIN branch");
        sqlite3_close(db);
        return;
    }

    PASS();
    sqlite3_close(db);
}

static void test_have_chain_sets_settle_window(void) {
    TEST("HAVE_CHAIN sets bootstrap_settle_until_ms in the future (H-4)");

    sqlite3 *db = NULL;
    if (setup_schema(&db) != 0) { FAIL("schema setup"); return; }

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    w.db = db;

    if (nodus_witness_db_migrate_v12(&w) != 0 ||
        insert_stub_block_1(db) != 0) {
        FAIL("setup");
        sqlite3_close(db);
        return;
    }

    uint64_t before = now_monotonic_ms();
    if (nodus_witness_bootstrap_start(&w) != 0) {
        FAIL("bootstrap_start");
        sqlite3_close(db);
        return;
    }

    if (w.bootstrap_settle_until_ms == 0) {
        FAIL("settle_until_ms should be set, not zero");
        sqlite3_close(db);
        return;
    }
    if (w.bootstrap_settle_until_ms <= before) {
        FAIL("settle_until_ms should be in the future per H-4");
        sqlite3_close(db);
        return;
    }
    PASS();
    sqlite3_close(db);
}

static void test_null_witness_rejected(void) {
    TEST("bootstrap_start rejects NULL witness handle");

    if (nodus_witness_bootstrap_start(NULL) == 0) {
        FAIL("NULL handle should return -1");
        return;
    }
    PASS();
}

/* C3 — DISCOVER state coverage. ──────────────────────────────────── */

/* Build a stub server config with the given seed_count. The DISCOVER
 * branch only reads seed_count for the C-1 gate; the actual seed
 * addresses are not exercised at the unit-test level.
 *
 * Heap-allocated because nodus_server_t embeds large session arrays
 * and transport structs that would overflow the default test stack. */
static nodus_server_t *make_server_with_seeds(int seed_count) {
    nodus_server_t *srv = (nodus_server_t *)calloc(1, sizeof(*srv));
    if (!srv) return NULL;
    srv->config.seed_count = seed_count;
    for (int i = 0; i < seed_count && i < (int)NODUS_MAX_SEED_NODES; i++) {
        snprintf(srv->config.seed_nodes[i],
                 sizeof(srv->config.seed_nodes[i]), "127.0.0.1");
        srv->config.seed_ports[i] = 14000 + (uint16_t)(i * 10);
    }
    return srv;
}

static void test_c1_gate_rejects_short_seed_list(void) {
    TEST("C-1 gate rejects empty DB + seed_count < committee_size");

    sqlite3 *db = NULL;
    if (setup_schema(&db) != 0) { FAIL("schema setup"); return; }

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    w.db = db;
    nodus_server_t *srv = make_server_with_seeds(DNAC_COMMITTEE_SIZE - 1);
    if (!srv) { FAIL("calloc server"); sqlite3_close(db); return; }
    w.server = srv;

    if (nodus_witness_db_migrate_v12(&w) != 0) {
        FAIL("migrate_v12");
        free(srv); sqlite3_close(db); return;
    }

    /* Empty DB (no block 1 inserted) + insufficient seeds → -1. */
    int rc = nodus_witness_bootstrap_start(&w);
    if (rc == 0) {
        FAIL("bootstrap_start should refuse C-1 gate violation");
        free(srv); sqlite3_close(db); return;
    }
    PASS();
    free(srv);
    sqlite3_close(db);
}

static void test_discover_entry_with_full_committee(void) {
    TEST("DISCOVER state entry on empty DB + committee_size seeds");

    sqlite3 *db = NULL;
    if (setup_schema(&db) != 0) { FAIL("schema setup"); return; }

    nodus_witness_t w;
    memset(&w, 0, sizeof(w));
    w.db = db;
    nodus_server_t *srv = make_server_with_seeds(DNAC_COMMITTEE_SIZE);
    if (!srv) { FAIL("calloc server"); sqlite3_close(db); return; }
    w.server = srv;

    if (nodus_witness_db_migrate_v12(&w) != 0) {
        FAIL("migrate_v12");
        free(srv); sqlite3_close(db); return;
    }

    int rc = nodus_witness_bootstrap_start(&w);
    if (rc != 0) {
        FAIL("bootstrap_start should accept C-1 gate at exact committee size");
        free(srv); sqlite3_close(db); return;
    }
    if (w.bootstrap_state != (int)NODUS_W_BOOTSTRAP_DISCOVER) {
        FAIL("expected state=DISCOVER on empty DB + sufficient seeds");
        free(srv); sqlite3_close(db); return;
    }
    if (w.bootstrap_attempt != 0) {
        FAIL("attempt should start at 0 — first tick increments it");
        free(srv); sqlite3_close(db); return;
    }
    PASS();
    free(srv);
    sqlite3_close(db);
}

int main(void) {
    printf("\nNodus Witness Auto-Bootstrap State Machine Tests\n");
    printf("=================================================\n\n");

    test_null_witness_rejected();
    test_have_chain_branch_reaches_done();
    test_have_chain_sets_settle_window();
    test_c1_gate_rejects_short_seed_list();
    test_discover_entry_with_full_committee();

    printf("\n=================================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
