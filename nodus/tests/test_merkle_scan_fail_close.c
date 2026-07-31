/**
 * Nodus — state_root leaf-scan fail-close tests (K3 / K3b)
 *
 * Every leaf loader in nodus_witness_merkle.c walks its table with
 * sqlite3_step and reduces the rows into a Merkle subtree of the
 * consensus state_root. Two ways that walk could silently truncate:
 *
 *   K3  — a mid-scan step error (SQLITE_IOERR / SQLITE_CORRUPT /
 *         SQLITE_FULL). The old loops were `while (sqlite3_step(stmt)
 *         == SQLITE_ROW)` with no post-loop rc check, so a scan that
 *         died on row 3 of 4 reported SUCCESS with 2 leaves — a
 *         silently divergent state_root, i.e. a chain split with no
 *         Byzantine actor.
 *
 *   K3b — a malformed row (wrong blob width). The old loops did
 *         `continue`, so two nodes holding DIFFERENT corrupt rows each
 *         dropped a different leaf and each reported success.
 *
 * Both must now fail the load (-1) instead.
 *
 * Fault injection is purely structural — no sleeps, no timing, no
 * randomness (flaky tests are forbidden project-wide):
 *
 *   - mid-scan step error: the table the loader reads is a VIEW over a
 *     raw table; one flagged row projects abs(-9223372036854775808),
 *     which SQLite evaluates per row and which raises "integer
 *     overflow" at step time. The base table's PRIMARY KEY gives the
 *     ORDER BY a usable index, so the scan streams and the error lands
 *     mid-walk (rows before it are returned first) rather than in a
 *     sorter pass.
 *   - malformed row: inserted directly with a short blob.
 *
 * Every fault case is paired with a NON-VACUITY twin: the identical
 * fixture with the fault disabled must still load successfully, so a
 * failure can only come from the injected fault and not from the
 * fixture itself.
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_merkle.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#define TEST(name) do { printf("  %-58s", name); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

/* SQL expression that raises SQLITE_ERROR ("integer overflow") when the
 * row is stepped over. abs() of the most negative int64 has no int64
 * result, and SQLite reports that at step time, per row. */
#define OVERFLOW_EXPR "abs(-9223372036854775808)"

/* nodus_witness_t is multi-MB — always heap-allocate the fixture. */
static nodus_witness_t *witness_new(void) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    if (sqlite3_open(":memory:", &w->db) != SQLITE_OK) {
        sqlite3_close(w->db);
        free(w);
        return NULL;
    }
    return w;
}

static void witness_free(nodus_witness_t *w) {
    if (!w) return;
    sqlite3_close(w->db);
    free(w);
}

static int exec_sql(nodus_witness_t *w, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(w->db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "sql error: %s\n  in: %s\n", err ? err : "?", sql);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

/* ── UTXO fixtures ─────────────────────────────────────────────────── */

/* utxo_set as a VIEW over utxo_raw. Row `bad_row` (1-based, 0 = none)
 * projects the overflow expression as its amount. */
static int utxo_view_fixture(nodus_witness_t *w, int bad_row) {
    if (exec_sql(w,
        "CREATE TABLE utxo_raw ("
        "  nullifier BLOB PRIMARY KEY,"
        "  owner TEXT NOT NULL,"
        "  amount INTEGER NOT NULL,"
        "  token_id BLOB NOT NULL,"
        "  tx_hash BLOB NOT NULL,"
        "  output_index INTEGER NOT NULL,"
        "  bad INTEGER NOT NULL DEFAULT 0"
        ");") != 0) return -1;

    if (exec_sql(w,
        "CREATE VIEW utxo_set AS SELECT nullifier, owner,"
        "  CASE WHEN bad = 1 THEN " OVERFLOW_EXPR " ELSE amount END AS amount,"
        "  token_id, tx_hash, output_index FROM utxo_raw;") != 0) return -1;

    for (int i = 1; i <= 4; i++) {
        uint8_t nullifier[64], token_id[64], tx_hash[64];
        char owner[129];
        memset(nullifier, (uint8_t)i, sizeof(nullifier));
        memset(token_id, 0, sizeof(token_id));
        memset(tx_hash, (uint8_t)(i ^ 0x55), sizeof(tx_hash));
        memset(owner, 'a', 128);
        owner[128] = '\0';

        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(w->db,
            "INSERT INTO utxo_raw (nullifier, owner, amount, token_id, "
            "tx_hash, output_index, bad) VALUES (?, ?, ?, ?, ?, ?, ?)",
            -1, &stmt, NULL) != SQLITE_OK) return -1;
        sqlite3_bind_blob(stmt, 1, nullifier, 64, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, owner, 128, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 3, (sqlite3_int64)(i * 1000));
        sqlite3_bind_blob(stmt, 4, token_id, 64, SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 5, tx_hash, 64, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 6, i);
        sqlite3_bind_int(stmt, 7, (i == bad_row) ? 1 : 0);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) return -1;
    }
    return 0;
}

/* Real utxo_set table. `short_row` (1-based, 0 = none) gets a 32-byte
 * nullifier instead of 64 — the malformed-row case. */
static int utxo_table_fixture(nodus_witness_t *w, int short_row) {
    if (exec_sql(w,
        "CREATE TABLE utxo_set ("
        "  nullifier BLOB PRIMARY KEY,"
        "  owner TEXT NOT NULL,"
        "  amount INTEGER NOT NULL,"
        "  token_id BLOB NOT NULL,"
        "  tx_hash BLOB NOT NULL,"
        "  output_index INTEGER NOT NULL"
        ");") != 0) return -1;

    for (int i = 1; i <= 4; i++) {
        uint8_t nullifier[64], token_id[64], tx_hash[64];
        char owner[129];
        memset(nullifier, (uint8_t)i, sizeof(nullifier));
        memset(token_id, 0, sizeof(token_id));
        memset(tx_hash, (uint8_t)(i ^ 0x55), sizeof(tx_hash));
        memset(owner, 'a', 128);
        owner[128] = '\0';

        int nlen = (i == short_row) ? 32 : 64;

        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(w->db,
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
            "tx_hash, output_index) VALUES (?, ?, ?, ?, ?, ?)",
            -1, &stmt, NULL) != SQLITE_OK) return -1;
        sqlite3_bind_blob(stmt, 1, nullifier, nlen, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, owner, 128, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 3, (sqlite3_int64)(i * 1000));
        sqlite3_bind_blob(stmt, 4, token_id, 64, SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 5, tx_hash, 64, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 6, i);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) return -1;
    }
    return 0;
}

/* ── Validator fixtures ────────────────────────────────────────────── */

/* Per-row fault kinds for validator_rows(). Applied to `fault_row` only. */
enum {
    VF_NONE = 0,
    VF_SHORT_PUBKEY,   /* pubkey blob 16 bytes instead of DNAC_PUBKEY_SIZE */
    VF_NULL_FP,        /* unstake_destination_fp = SQL NULL                */
    VF_LONG_FP,        /* unstake_destination_fp longer than the 128 window */
    VF_EMPTY_FP,       /* unstake_destination_fp = "" — LEGITIMATE          */
    VF_SHORT_UPK       /* unstake_destination_pubkey blob 16 bytes          */
};

/* NOTE: the fp / upk columns are declared WITHOUT the production schema's
 * NOT NULL constraint (nodus_witness.c:158-159) so VF_NULL_FP can be
 * injected at all.
 *
 * On an honest chain DB a SQL NULL there is UNREACHABLE — the constraint
 * holds and there is no `ALTER TABLE validators` anywhere in nodus/src to
 * have dropped it. So this case pins DEFENCE, not a live shape: a
 * restored or in-place-corrupted file can still present a NULL, and the
 * leaf builder is what stands between that and a substituted value inside
 * state_root. */
static const char *VALIDATOR_COLUMNS =
    "  pubkey BLOB PRIMARY KEY,"
    "  self_stake INTEGER NOT NULL,"
    "  total_delegated INTEGER NOT NULL,"
    "  external_delegated INTEGER NOT NULL,"
    "  commission_bps INTEGER NOT NULL,"
    "  pending_commission_bps INTEGER NOT NULL,"
    "  pending_effective_block INTEGER NOT NULL,"
    "  status INTEGER NOT NULL,"
    "  active_since_block INTEGER NOT NULL,"
    "  unstake_commit_block INTEGER NOT NULL,"
    "  unstake_destination_fp TEXT,"
    "  unstake_destination_pubkey BLOB,"
    "  last_validator_update_block INTEGER NOT NULL,"
    "  consecutive_missed_epochs INTEGER NOT NULL,"
    "  last_signed_block INTEGER NOT NULL,"
    "  signed_blocks_this_epoch INTEGER NOT NULL";

/* Insert 4 validator rows into `table`. Row `fault_row` (1-based,
 * 0 = none) gets the malformed value named by `fault_kind`. `bad_row`
 * flags the step-error row when the table carries a `bad` column (view
 * fixture only). */
static int validator_rows(nodus_witness_t *w, const char *table,
                          int has_bad, int bad_row,
                          int fault_kind, int fault_row) {
    /* 200 chars — longer than the 128-byte leaf window, which used to be
     * silently truncated (two rows differing only past byte 128 hashed
     * identically). */
    char long_fp[201];
    memset(long_fp, 'f', sizeof(long_fp) - 1);
    long_fp[sizeof(long_fp) - 1] = '\0';

    for (int i = 1; i <= 4; i++) {
        uint8_t pubkey[DNAC_PUBKEY_SIZE];
        memset(pubkey, (uint8_t)i, sizeof(pubkey));
        int faulty = (i == fault_row);

        int pklen  = (faulty && fault_kind == VF_SHORT_PUBKEY)
                         ? 16 : DNAC_PUBKEY_SIZE;
        int upklen = (faulty && fault_kind == VF_SHORT_UPK)
                         ? 16 : DNAC_PUBKEY_SIZE;

        char sql[768];
        snprintf(sql, sizeof(sql),
            "INSERT INTO %s (pubkey, self_stake, total_delegated,"
            " external_delegated, commission_bps, pending_commission_bps,"
            " pending_effective_block, status, active_since_block,"
            " unstake_commit_block, unstake_destination_fp,"
            " unstake_destination_pubkey, last_validator_update_block,"
            " consecutive_missed_epochs, last_signed_block,"
            " signed_blocks_this_epoch%s) VALUES (?, 10, 0, 0, 100, 0, 0, 1,"
            " 1, 0, ?, ?, 0, 0, 0, 0%s)",
            table, has_bad ? ", bad" : "", has_bad ? ", ?" : "");

        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_blob(stmt, 1, pubkey, pklen, SQLITE_STATIC);

        if (faulty && fault_kind == VF_NULL_FP) {
            sqlite3_bind_null(stmt, 2);
        } else if (faulty && fault_kind == VF_LONG_FP) {
            sqlite3_bind_text(stmt, 2, long_fp, -1, SQLITE_STATIC);
        } else if (faulty && fault_kind == VF_EMPTY_FP) {
            /* An EMPTY (not NULL) text value — what the genesis seeder
             * stores when a chain_def's iv_fp begins with a NUL byte:
             * nodus_witness_genesis_seed.c:117 copies it verbatim and
             * nodus_witness_validator.c:64-66 binds it with length -1
             * (strlen). This must keep loading. */
            sqlite3_bind_text(stmt, 2, "", -1, SQLITE_STATIC);
        } else {
            sqlite3_bind_text(stmt, 2, "fp", -1, SQLITE_STATIC);
        }

        sqlite3_bind_blob(stmt, 3, pubkey, upklen, SQLITE_STATIC);
        if (has_bad) sqlite3_bind_int(stmt, 4, (i == bad_row) ? 1 : 0);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) return -1;
    }
    return 0;
}

static int validator_view_fixture(nodus_witness_t *w, int bad_row) {
    char sql[2048];
    snprintf(sql, sizeof(sql),
             "CREATE TABLE validators_raw (%s, bad INTEGER NOT NULL DEFAULT 0);",
             VALIDATOR_COLUMNS);
    if (exec_sql(w, sql) != 0) return -1;

    if (exec_sql(w,
        "CREATE VIEW validators AS SELECT pubkey,"
        "  CASE WHEN bad = 1 THEN " OVERFLOW_EXPR " ELSE self_stake END"
        "    AS self_stake,"
        "  total_delegated, external_delegated, commission_bps,"
        "  pending_commission_bps, pending_effective_block, status,"
        "  active_since_block, unstake_commit_block, unstake_destination_fp,"
        "  unstake_destination_pubkey, last_validator_update_block,"
        "  consecutive_missed_epochs, last_signed_block,"
        "  signed_blocks_this_epoch FROM validators_raw;") != 0) return -1;

    return validator_rows(w, "validators_raw", 1, bad_row, VF_NONE, 0);
}

/* Real `validators` table with one row carrying `fault_kind`. */
static int validator_fault_fixture(nodus_witness_t *w, int fault_kind,
                                   int fault_row) {
    char sql[2048];
    snprintf(sql, sizeof(sql), "CREATE TABLE validators (%s);",
             VALIDATOR_COLUMNS);
    if (exec_sql(w, sql) != 0) return -1;
    return validator_rows(w, "validators", 0, 0, fault_kind, fault_row);
}

static int validator_table_fixture(nodus_witness_t *w, int fault_row) {
    return validator_fault_fixture(w, VF_SHORT_PUBKEY, fault_row);
}

static int validator_null_fp_fixture(nodus_witness_t *w, int fault_row) {
    return validator_fault_fixture(w, VF_NULL_FP, fault_row);
}

static int validator_long_fp_fixture(nodus_witness_t *w, int fault_row) {
    return validator_fault_fixture(w, VF_LONG_FP, fault_row);
}

static int validator_short_upk_fixture(nodus_witness_t *w, int fault_row) {
    return validator_fault_fixture(w, VF_SHORT_UPK, fault_row);
}

/* ── Delegation fixtures ───────────────────────────────────────────── */

/* Column list only — the table-level PRIMARY KEY constraint is appended
 * by the fixtures AFTER any extra column, since SQLite rejects a column
 * definition that follows a table constraint. The PK order matches the
 * loader's ORDER BY so the scan streams off the index. */
static const char *DELEGATION_COLUMNS =
    "  delegator_pubkey BLOB NOT NULL,"
    "  validator_pubkey BLOB NOT NULL,"
    "  amount INTEGER NOT NULL,"
    "  delegated_at_block INTEGER NOT NULL";

#define DELEGATION_PK "PRIMARY KEY (validator_pubkey, delegator_pubkey)"

static int delegation_rows(nodus_witness_t *w, const char *table,
                           int has_bad, int bad_row, int short_row) {
    for (int i = 1; i <= 4; i++) {
        uint8_t dpk[DNAC_PUBKEY_SIZE], vpk[DNAC_PUBKEY_SIZE];
        memset(dpk, (uint8_t)i, sizeof(dpk));
        memset(vpk, (uint8_t)(0x80 + i), sizeof(vpk));
        int dlen = (i == short_row) ? 16 : DNAC_PUBKEY_SIZE;

        char sql[512];
        snprintf(sql, sizeof(sql),
            "INSERT INTO %s (delegator_pubkey, validator_pubkey, amount,"
            " delegated_at_block%s) VALUES (?, ?, 5, 1%s)",
            table, has_bad ? ", bad" : "", has_bad ? ", ?" : "");

        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_blob(stmt, 1, dpk, dlen, SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 2, vpk, DNAC_PUBKEY_SIZE, SQLITE_STATIC);
        if (has_bad) sqlite3_bind_int(stmt, 3, (i == bad_row) ? 1 : 0);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) return -1;
    }
    return 0;
}

static int delegation_view_fixture(nodus_witness_t *w, int bad_row) {
    char sql[1024];
    snprintf(sql, sizeof(sql),
             "CREATE TABLE delegations_raw (%s, bad INTEGER NOT NULL "
             "DEFAULT 0, " DELEGATION_PK ");",
             DELEGATION_COLUMNS);
    if (exec_sql(w, sql) != 0) return -1;

    if (exec_sql(w,
        "CREATE VIEW delegations AS SELECT delegator_pubkey,"
        "  validator_pubkey,"
        "  CASE WHEN bad = 1 THEN " OVERFLOW_EXPR " ELSE amount END AS amount,"
        "  delegated_at_block FROM delegations_raw;") != 0) return -1;

    return delegation_rows(w, "delegations_raw", 1, bad_row, 0);
}

static int delegation_table_fixture(nodus_witness_t *w, int short_row) {
    char sql[1024];
    snprintf(sql, sizeof(sql), "CREATE TABLE delegations (%s, "
             DELEGATION_PK ");", DELEGATION_COLUMNS);
    if (exec_sql(w, sql) != 0) return -1;
    return delegation_rows(w, "delegations", 0, 0, short_row);
}

/* ── epoch_state fixtures ──────────────────────────────────────────── */

/* Present but EMPTY. load_epoch_state_leaves reads the supply counters
 * before it touches epoch_state, and since the D1/D3 change merged a
 * MISSING supply_tracking is a hard error there (supply_get returns -1
 * for "no such table"), not "pre-genesis". Without this the clean run of
 * every epoch_state case would fail too and the fault case would be
 * vacuous. An empty table yields supply_get == 1, which IS pre-genesis. */
static int create_empty_supply_tracking(nodus_witness_t *w) {
    return exec_sql(w,
        "CREATE TABLE supply_tracking ("
        "  id INTEGER PRIMARY KEY CHECK(id = 1),"
        "  genesis_supply INTEGER NOT NULL,"
        "  total_burned INTEGER NOT NULL DEFAULT 0,"
        "  total_minted INTEGER NOT NULL DEFAULT 0,"
        "  current_supply INTEGER NOT NULL,"
        "  last_tx_hash BLOB NOT NULL,"
        "  last_sequence INTEGER NOT NULL"
        ");");
}

/* Insert 4 epoch_state rows. `short_row` (1-based, 0 = none) gets a
 * 32-byte snapshot_hash instead of 64. */
static int epoch_state_rows(nodus_witness_t *w, const char *table,
                            int has_bad, int bad_row, int short_row) {
    for (int i = 1; i <= 4; i++) {
        uint8_t snap[64];
        memset(snap, (uint8_t)i, sizeof(snap));
        int snaplen = (i == short_row) ? 32 : 64;

        char sql[512];
        snprintf(sql, sizeof(sql),
            "INSERT INTO %s (epoch_start_height, epoch_pool_accum,"
            " snapshot_hash%s) VALUES (?, ?, ?%s)",
            table, has_bad ? ", bad" : "", has_bad ? ", ?" : "");

        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_int64(stmt, 1, (sqlite3_int64)(i * 10));
        sqlite3_bind_int64(stmt, 2, (sqlite3_int64)i);
        sqlite3_bind_blob(stmt, 3, snap, snaplen, SQLITE_STATIC);
        if (has_bad) sqlite3_bind_int(stmt, 4, (i == bad_row) ? 1 : 0);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) return -1;
    }
    return 0;
}

static int epoch_state_view_fixture(nodus_witness_t *w, int bad_row) {
    if (create_empty_supply_tracking(w) != 0) return -1;

    if (exec_sql(w,
        "CREATE TABLE epoch_state_raw ("
        "  epoch_start_height INTEGER PRIMARY KEY,"
        "  epoch_pool_accum INTEGER NOT NULL,"
        "  snapshot_hash BLOB NOT NULL,"
        "  bad INTEGER NOT NULL DEFAULT 0"
        ");") != 0) return -1;

    if (exec_sql(w,
        "CREATE VIEW epoch_state AS SELECT epoch_start_height,"
        "  CASE WHEN bad = 1 THEN " OVERFLOW_EXPR " ELSE epoch_pool_accum END"
        "    AS epoch_pool_accum,"
        "  snapshot_hash FROM epoch_state_raw;") != 0) return -1;

    return epoch_state_rows(w, "epoch_state_raw", 1, bad_row, 0);
}

static int epoch_state_table_fixture(nodus_witness_t *w, int short_row) {
    if (create_empty_supply_tracking(w) != 0) return -1;

    if (exec_sql(w,
        "CREATE TABLE epoch_state ("
        "  epoch_start_height INTEGER PRIMARY KEY,"
        "  epoch_pool_accum INTEGER NOT NULL,"
        "  snapshot_hash BLOB NOT NULL"
        ");") != 0) return -1;

    return epoch_state_rows(w, "epoch_state", 0, 0, short_row);
}

/* ── Composite fixture ─────────────────────────────────────────────── */

/* The four subtrees compute_state_root needs besides utxo, created EMPTY
 * so each returns its tagged-empty sentinel, plus supply_tracking.
 *
 * All five are required since the D1-D4 change merged: compute_state_root
 * now fails closed on every subtree (the tagged-empty fallbacks it used
 * to substitute are gone), and load_epoch_state_leaves fails closed when
 * nodus_witness_supply_get reports a DB error — which is what a missing
 * supply_tracking table produces. An empty-but-present supply_tracking
 * reports "row absent" (1) instead, which is the legitimate pre-genesis
 * state and keeps the clean run green. */
static int create_companion_tables(nodus_witness_t *w) {
    char sql[2048];

    snprintf(sql, sizeof(sql), "CREATE TABLE validators (%s);",
             VALIDATOR_COLUMNS);
    if (exec_sql(w, sql) != 0) return -1;

    snprintf(sql, sizeof(sql), "CREATE TABLE delegations (%s, "
             DELEGATION_PK ");", DELEGATION_COLUMNS);
    if (exec_sql(w, sql) != 0) return -1;

    if (exec_sql(w,
        "CREATE TABLE epoch_state ("
        "  epoch_start_height INTEGER PRIMARY KEY,"
        "  epoch_pool_accum INTEGER NOT NULL,"
        "  snapshot_hash BLOB NOT NULL"
        ");") != 0) return -1;

    if (exec_sql(w,
        "CREATE TABLE chain_config_history ("
        "  param_id INTEGER NOT NULL,"
        "  new_value INTEGER NOT NULL,"
        "  effective_block INTEGER NOT NULL,"
        "  commit_block INTEGER NOT NULL,"
        "  proposal_nonce INTEGER NOT NULL"
        ");") != 0) return -1;

    return create_empty_supply_tracking(w);
}

static int composite_fixture(nodus_witness_t *w, int bad_row) {
    if (utxo_view_fixture(w, bad_row) != 0) return -1;
    return create_companion_tables(w);
}

/* ── Test driver ───────────────────────────────────────────────────── */

typedef int (*fixture_fn)(nodus_witness_t *w, int fault_row);
typedef int (*root_fn)(nodus_witness_t *w, uint8_t *root_out);

/* Runs `fixture` twice: once clean (fault_row 0, must LOAD) and once
 * with the fault on row 3 (must FAIL). The clean run is the
 * non-vacuity proof — it shows the failure comes from the fault and
 * not from the fixture. */
static void run_case(const char *name, fixture_fn fixture, root_fn root) {
    TEST(name);

    /* Named root_buf, not root: `root` is this function's root_fn
     * parameter. */
    uint8_t root_buf[64];

    nodus_witness_t *clean = witness_new();
    if (!clean) { FAIL("alloc clean"); return; }
    if (fixture(clean, 0) != 0) { FAIL("clean fixture"); witness_free(clean); return; }
    if (root(clean, root_buf) != 0) {
        FAIL("clean fixture did not load — fault case would be vacuous");
        witness_free(clean);
        return;
    }
    witness_free(clean);

    nodus_witness_t *faulty = witness_new();
    if (!faulty) { FAIL("alloc faulty"); return; }
    if (fixture(faulty, 3) != 0) { FAIL("faulty fixture"); witness_free(faulty); return; }
    if (root(faulty, root_buf) == 0) {
        FAIL("load reported SUCCESS on a truncated/malformed scan");
        witness_free(faulty);
        return;
    }
    witness_free(faulty);

    PASS();
}

/* An EMPTY unstake_destination_fp is a reachable honest value — a genesis
 * chain_def whose iv_fp starts with a NUL byte produces one
 * (nodus_witness_genesis_seed.c:117) — and it must keep loading. The fp
 * fail-close rejects a SQL NULL and an over-long value, NOT an empty one.
 * Without this pin, tightening the check to `!fp` would reject that
 * genesis shape outright, which is a total consensus halt rather than the
 * divergence the check exists to prevent.
 *
 * (It is NOT, as an earlier version of this comment claimed, "every
 * validator that never requested unstaking" — the fp is set full at STAKE
 * time, nodus_witness_bft.c:1455-1456, and is immutable afterwards.) */
static void test_empty_fp_still_loads(void) {
    TEST("validator with EMPTY unstake_destination_fp still loads");

    nodus_witness_t *w = witness_new();
    if (!w) { FAIL("alloc"); return; }
    if (validator_fault_fixture(w, VF_EMPTY_FP, 3) != 0) {
        FAIL("fixture"); witness_free(w); return;
    }

    uint8_t root[64];
    if (nodus_witness_merkle_compute_validator_root(w, root) != 0) {
        FAIL("empty fp rejected — this would halt every honest validator");
        witness_free(w);
        return;
    }
    witness_free(w);
    PASS();
}

/* And the empty-fp leaf must be a REAL digest: deterministic across
 * recomputation and not the all-zero sentinel the failure paths write.
 * (Byte-equality against the pre-change encoding cannot be asserted from
 * here — the old code is gone — but the encoding itself is untouched:
 * an empty fp still hashes the same zero-padded 128-byte window.) */
static void test_empty_fp_root_is_real(void) {
    TEST("empty-fp validator root is a real, stable digest");

    nodus_witness_t *w = witness_new();
    if (!w) { FAIL("alloc"); return; }
    if (validator_fault_fixture(w, VF_EMPTY_FP, 3) != 0) {
        FAIL("fixture"); witness_free(w); return;
    }

    uint8_t a[64], b[64], zero[64];
    memset(zero, 0, sizeof(zero));
    if (nodus_witness_merkle_compute_validator_root(w, a) != 0 ||
        nodus_witness_merkle_compute_validator_root(w, b) != 0) {
        FAIL("compute failed"); witness_free(w); return;
    }
    witness_free(w);

    if (memcmp(a, b, 64) != 0) { FAIL("not deterministic"); return; }
    if (memcmp(a, zero, 64) == 0) { FAIL("all-zero root"); return; }
    PASS();
}

/* Item 4 — the two hash helpers that used to return void now report
 * failure. Their EVP-failure path cannot be provoked without mocking
 * OpenSSL, but the NULL-argument leg is reachable and is the same
 * contract: a caller must be able to tell "no root" from "a root". */
static void test_hash_helpers_report_failure(void) {
    TEST("empty_root / combine_v3 report failure instead of zeros");

    uint8_t out[64];
    uint8_t sub[64];
    memset(sub, 0x11, sizeof(sub));

    if (nodus_merkle_empty_root(NODUS_TREE_TAG_VALIDATOR, NULL) == 0) {
        FAIL("empty_root(NULL) reported success"); return;
    }
    if (nodus_merkle_empty_root(NODUS_TREE_TAG_VALIDATOR, out) != 0) {
        FAIL("empty_root failed on a valid call"); return;
    }

    if (nodus_merkle_combine_state_root_v3(sub, sub, sub, sub, sub,
                                            NULL) == 0) {
        FAIL("combine_v3(out=NULL) reported success"); return;
    }
    if (nodus_merkle_combine_state_root_v3(NULL, sub, sub, sub, sub,
                                            out) == 0) {
        FAIL("combine_v3(utxo=NULL) reported success"); return;
    }
    if (nodus_merkle_combine_state_root_v3(sub, sub, sub, sub, sub,
                                            out) != 0) {
        FAIL("combine_v3 failed on a valid call"); return;
    }

    /* Non-vacuity: a valid combine produces a real digest, not the
     * all-zero sentinel the failure path writes. */
    uint8_t zero[64];
    memset(zero, 0, sizeof(zero));
    if (memcmp(out, zero, 64) == 0) { FAIL("valid combine produced zeros"); return; }

    PASS();
}

int main(void) {
    printf("\nNodus state_root leaf-scan fail-close tests (K3 / K3b)\n");
    printf("============================================================\n\n");

    /* K3 — mid-scan step error must fail the load, per subtree. */
    run_case("K3  utxo scan error is not silent truncation",
             utxo_view_fixture, nodus_witness_merkle_compute_utxo_root);
    run_case("K3  validator scan error is not silent truncation",
             validator_view_fixture, nodus_witness_merkle_compute_validator_root);
    run_case("K3  delegation scan error is not silent truncation",
             delegation_view_fixture, nodus_witness_merkle_compute_delegation_root);
    run_case("K3  epoch_state scan error is not silent truncation",
             epoch_state_view_fixture, nodus_witness_merkle_compute_epoch_state_root);

    /* K3 — the composite state_root inherits a mid-scan step error.
     *
     * MERGE NOTE (2026-07-31): this case used to run on a utxo-only
     * fixture and lean on compute_state_root substituting tagged-empty
     * sentinels for the four other subtrees. The D1-D4 change deleted
     * those fallbacks — every subtree now fails closed — so the fixture
     * builds all five subtree tables (empty) plus supply_tracking, and
     * the ONLY difference between the clean and faulty runs is the
     * injected utxo step error. Fault-mode coverage that the merged
     * test_witness_state_root_failclose does not have: it injects
     * DROP TABLE (prepare fails), this injects a mid-SCAN step error
     * after rows have already been returned. */
    run_case("K3  composite state_root fails when utxo scan errors",
             composite_fixture, nodus_witness_merkle_compute_state_root);

    /* K3b — a malformed row fails the load instead of being skipped. */
    run_case("K3b utxo malformed row fails the load",
             utxo_table_fixture, nodus_witness_merkle_compute_utxo_root);
    run_case("K3b validator malformed row fails the load",
             validator_table_fixture, nodus_witness_merkle_compute_validator_root);
    run_case("K3b delegation malformed row fails the load",
             delegation_table_fixture, nodus_witness_merkle_compute_delegation_root);

    /* Round-3 item 3 — the three columns that still substituted zeros
     * INSIDE a leaf the loops above already guarded. Each one made two
     * nodes with different corruption produce different roots while both
     * reported success. */
    run_case("R3  validator NULL unstake_destination_fp fails the load",
             validator_null_fp_fixture,
             nodus_witness_merkle_compute_validator_root);
    run_case("R3  validator over-long unstake_destination_fp fails the load",
             validator_long_fp_fixture,
             nodus_witness_merkle_compute_validator_root);
    run_case("R3  validator short unstake_destination_pubkey fails the load",
             validator_short_upk_fixture,
             nodus_witness_merkle_compute_validator_root);
    run_case("R3  epoch_state short snapshot_hash fails the load",
             epoch_state_table_fixture,
             nodus_witness_merkle_compute_epoch_state_root);

    /* …and the non-vacuity guards for that fail-close: an EMPTY fp is a
     * legitimate value and must still load. */
    test_empty_fp_still_loads();
    test_empty_fp_root_is_real();

    /* Round-3 item 4 — the void hash helpers now report failure. */
    test_hash_helpers_report_failure();

    printf("\n============================================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
