/**
 * Nodus — state_root GOLDEN VECTOR (cross-version composition pin)
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * Before a production deploy the question that has to be answered is:
 * does a node running the OLD build and a node running the NEW build
 * compute the SAME state_root for the SAME state? Nothing in the tree
 * answered it. test_merkle_utxo_root.c is purely RELATIONAL — it asserts
 * "same input -> same root" (:100) and "amount flip -> different root"
 * (:128). Both hold just as well AFTER a format change, because r1 and
 * r2 move together. A relational test can never catch a composition
 * change; only a pinned value can.
 *
 * So this test nails a CONSTANT: one fixed, fully-specified chain state
 * hashes to one fixed 64-byte state_root. Any change to a leaf preimage,
 * a domain tag, a field order, an endianness, the RFC 6962 reduction, or
 * the v3 combiner moves that constant and this test goes red.
 *
 * WHAT IS PINNED
 * --------------
 * nodus_witness_merkle_compute_state_root (nodus_witness_merkle.c:1387)
 * combines FIVE subtree roots through nodus_merkle_combine_state_root_v3:
 *
 *   utxo_root          nodus_witness_merkle.c:180  (load_utxo_leaves)
 *   validator_root     nodus_witness_merkle.c:1086 (compute_validator_root)
 *   delegation_root    nodus_witness_merkle.c:1200 (compute_delegation_root)
 *   epoch_state_root   nodus_witness_merkle.c:1345 (compute_epoch_state_root)
 *   chain_config_root  nodus_witness_chain_config.c:314
 *
 * The fixture below populates ALL FIVE with real rows, so no input is a
 * tagged-empty sentinel and every one of the five contributes bytes to
 * the pinned value. The five non-vacuity cases prove that claim rather
 * than asserting it: each mutates exactly one table and requires the
 * root to move. A sixth does the same for supply_tracking, whose
 * total_minted / total_burned counters are hashed into every
 * epoch_state leaf (nodus_witness_merkle.c:1322-1325) and are therefore
 * inside state_root without having a subtree of their own.
 *
 * HOW TO FILL THE GOLDEN VALUE
 * ----------------------------
 *   ./test_merkle_state_root_golden --print-root
 *
 * prints the computed root as a paste-ready C initializer and exits 0.
 * The value is produced by the ORCHESTRATOR against the OLD commit, then
 * pasted here, so the pin encodes the PRE-deploy composition and the new
 * build has to reproduce it.
 *
 * DETERMINISM
 * -----------
 * Every value in the fixture is a compile-time constant. No rand(), no
 * time(), no getenv, no pointer values, no iteration over anything but
 * SQLite result sets that the PRODUCTION queries themselves order:
 *   utxo         ORDER BY nullifier ASC                  (:188)
 *   validators   ORDER BY pubkey ASC                     (:912)
 *   delegations  ORDER BY validator_pubkey, delegator_pubkey (:1131)
 *   epoch_state  ORDER BY epoch_start_height ASC         (:1269)
 *   chain_config ORDER BY effective_block, param_id, commit_block,
 *                         proposal_nonce                 (:321-322)
 * Those are BLOB (memcmp) and INTEGER orderings — no collation, no
 * locale, no platform dependence. The fixture additionally gives every
 * row a DISTINCT value in every sort key, so no tie is ever broken by
 * insertion order or by the query planner.
 */

#include "witness/nodus_witness_merkle.h"
#include "witness/nodus_witness.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#define TEST(name) do { printf("  %-55s", name); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

/* ── The pin ───────────────────────────────────────────────────────────
 *
 * PLACEHOLDER. All-zero means UNFILLED, and while it is unfilled the
 * golden check FAILS CLOSED — it never silently passes, the same
 * discipline as the zk *_UNFILLED pins (shared/crypto/zk/fri_air_table.h
 * :399-401).
 *
 * The ORCHESTRATOR fills this by running `--print-root` against the
 * pre-deploy commit and pasting the output here. It is deliberately NOT
 * filled by whoever wrote this file: a value produced by the same build
 * it is meant to police would pin nothing. */
/* GENERATED ON THE OLD CODE, ON PURPOSE.
 *
 * These 64 bytes were produced by `--print-root` built at commit 2bb59883 —
 * the version running in production before the v0.18.19/v0.18.20 witness
 * fail-close work — and NOT by the build this test now guards. A golden value
 * produced by the code it is meant to police pins nothing; generating it on
 * the OLD side is what makes "the new code still agrees" a real claim.
 *
 * The comparison was run: 2bb59883 and d61e658a emit byte-identical roots for
 * this fixture, which is the evidence that the fail-close rewrite did not move
 * the state_root composition and that a rolling deploy cannot split the chain
 * on the happy path.
 *
 * ⚠ If this ever fails, do NOT regenerate it to make the build green. A moved
 * root means the state_root FORMAT changed, and that turns a rolling deploy
 * into a stop-all + archive + chain-wipe decision. */
static const uint8_t GOLDEN_STATE_ROOT[64] = {
    0xbd, 0x5a, 0xe5, 0x2f, 0xc7, 0x80, 0xb5, 0x57,
    0x5a, 0xe5, 0x66, 0x27, 0xe3, 0xbe, 0xed, 0x9f,
    0x04, 0x08, 0xed, 0x58, 0x93, 0xd5, 0x32, 0xfb,
    0x1d, 0xe3, 0xde, 0x0a, 0x20, 0xb4, 0xfd, 0x12,
    0x5e, 0x8d, 0x79, 0xa9, 0x37, 0xdb, 0x4c, 0xfb,
    0xee, 0x18, 0x6b, 0x14, 0x08, 0x42, 0x64, 0x1b,
    0x9c, 0x17, 0x5f, 0x22, 0x13, 0x8f, 0xe7, 0x39,
    0xd8, 0xa7, 0x8f, 0x41, 0x3a, 0x32, 0x4c, 0x0f,
};

static int golden_is_unfilled(void) {
    for (size_t i = 0; i < sizeof(GOLDEN_STATE_ROOT); i++)
        if (GOLDEN_STATE_ROOT[i] != 0) return 0;
    return 1;
}

/* ── Fixture ───────────────────────────────────────────────────────────
 *
 * nodus_witness_t is multi-MB — heap-allocate it. A stack fixture
 * segfaults (feedback_heap_alloc_test_fixture). */
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

/* Column-for-column the production schema:
 *   utxo_set / validators / delegations / epoch_state / supply_tracking
 *     nodus_witness.c:55-67, :146-164, :167-175, :181-186, :199-207
 *   chain_config_history
 *     nodus_witness_chain_config.c:96-105
 * Copied rather than obtained through nodus_witness_open() so the test
 * needs no filesystem and no genesis, and so the exact shape being
 * hashed is visible in this file. */
static int create_schema(nodus_witness_t *w) {
    return exec_sql(w,
        "CREATE TABLE utxo_set ("
        "  nullifier BLOB PRIMARY KEY,"
        "  owner TEXT NOT NULL,"
        "  amount INTEGER NOT NULL,"
        "  token_id BLOB NOT NULL,"
        "  tx_hash BLOB NOT NULL,"
        "  output_index INTEGER NOT NULL,"
        "  block_height INTEGER NOT NULL DEFAULT 0,"
        "  created_at INTEGER NOT NULL DEFAULT 0"
        ");"
        "CREATE TABLE validators ("
        "  pubkey_hash BLOB PRIMARY KEY,"
        "  pubkey BLOB NOT NULL,"
        "  self_stake INTEGER NOT NULL,"
        "  total_delegated INTEGER NOT NULL DEFAULT 0,"
        "  external_delegated INTEGER NOT NULL DEFAULT 0,"
        "  commission_bps INTEGER NOT NULL,"
        "  pending_commission_bps INTEGER NOT NULL DEFAULT 0,"
        "  pending_effective_block INTEGER NOT NULL DEFAULT 0,"
        "  status INTEGER NOT NULL,"
        "  active_since_block INTEGER NOT NULL,"
        "  unstake_commit_block INTEGER NOT NULL DEFAULT 0,"
        "  unstake_destination_fp TEXT NOT NULL,"
        "  unstake_destination_pubkey BLOB NOT NULL,"
        "  last_validator_update_block INTEGER NOT NULL DEFAULT 0,"
        "  consecutive_missed_epochs INTEGER NOT NULL DEFAULT 0,"
        "  last_signed_block INTEGER NOT NULL DEFAULT 0,"
        "  signed_blocks_this_epoch INTEGER NOT NULL DEFAULT 0"
        ");"
        "CREATE TABLE delegations ("
        "  delegator_hash BLOB,"
        "  validator_hash BLOB,"
        "  delegator_pubkey BLOB NOT NULL,"
        "  validator_pubkey BLOB NOT NULL,"
        "  amount INTEGER NOT NULL,"
        "  delegated_at_block INTEGER NOT NULL,"
        "  PRIMARY KEY (delegator_hash, validator_hash)"
        ");"
        "CREATE TABLE epoch_state ("
        "  epoch_start_height INTEGER PRIMARY KEY,"
        "  epoch_pool_accum   INTEGER NOT NULL DEFAULT 0,"
        "  snapshot_hash      BLOB NOT NULL,"
        "  snapshot_blob      BLOB"
        ");"
        "CREATE TABLE supply_tracking ("
        "  id INTEGER PRIMARY KEY CHECK(id = 1),"
        "  genesis_supply INTEGER NOT NULL,"
        "  total_burned INTEGER NOT NULL DEFAULT 0,"
        "  total_minted INTEGER NOT NULL DEFAULT 0,"
        "  current_supply INTEGER NOT NULL,"
        "  last_tx_hash BLOB NOT NULL,"
        "  last_sequence INTEGER NOT NULL"
        ");"
        "CREATE TABLE chain_config_history ("
        "  param_id          INTEGER NOT NULL,"
        "  new_value         INTEGER NOT NULL,"
        "  effective_block   INTEGER NOT NULL,"
        "  commit_block      INTEGER NOT NULL,"
        "  tx_hash           BLOB    NOT NULL,"
        "  proposal_nonce    INTEGER NOT NULL,"
        "  created_at_unix   INTEGER NOT NULL,"
        "  PRIMARY KEY (param_id, effective_block)"
        ");");
}

/* Fixed 128-char owner fingerprint for UTXO row i. The production leaf
 * hashes exactly 128 bytes of it (nodus_witness_merkle.c:145-153), so a
 * full-length value is what a real chain stores. */
static void fill_owner_fp(char out[129], int i) {
    static const char hex[] = "0123456789abcdef";
    for (int j = 0; j < 128; j++) out[j] = hex[(i * 7 + j) & 0xf];
    out[128] = '\0';
}

/* 3 UTXO rows. Distinct nullifiers => the ORDER BY nullifier ASC scan
 * has a total order with no ties. 3 leaves also exercises the odd-node
 * promotion branch of the RFC 6962 reduction, which 2 or 4 would not. */
static int insert_utxos(nodus_witness_t *w) {
    for (int i = 1; i <= 3; i++) {
        uint8_t nullifier[64], token_id[64], tx_hash[64];
        char owner[129];
        memset(nullifier, (uint8_t)(0x10 + i), sizeof(nullifier));
        memset(token_id, 0, sizeof(token_id));   /* native DNAC token */
        memset(tx_hash, (uint8_t)(0xa0 + i), sizeof(tx_hash));
        fill_owner_fp(owner, i);

        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(w->db,
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id,"
            " tx_hash, output_index) VALUES (?, ?, ?, ?, ?, ?)",
            -1, &stmt, NULL) != SQLITE_OK) return -1;
        sqlite3_bind_blob(stmt, 1, nullifier, 64, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, owner, 128, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 3, (sqlite3_int64)(1000000 * i + 7));
        sqlite3_bind_blob(stmt, 4, token_id, 64, SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 5, tx_hash, 64, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 6, i);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) return -1;
    }
    return 0;
}

/* 3 validator rows — again odd, again distinct in the sort key
 * (pubkey). unstake_destination_fp is a full 128-char hex string, which
 * is what STAKE writes (nodus_witness_bft.c:1455-1456); an empty fp is
 * legal but is the rarer genesis-seeder shape, so the common one is
 * pinned here. */
static int insert_validators(nodus_witness_t *w) {
    for (int i = 1; i <= 3; i++) {
        uint8_t pubkey_hash[64], pubkey[DNAC_PUBKEY_SIZE];
        uint8_t upk[DNAC_PUBKEY_SIZE];
        char fp[129];
        memset(pubkey_hash, (uint8_t)(0x30 + i), sizeof(pubkey_hash));
        memset(pubkey, (uint8_t)(0x40 + i), sizeof(pubkey));
        memset(upk, (uint8_t)(0x50 + i), sizeof(upk));
        fill_owner_fp(fp, i + 3);

        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(w->db,
            "INSERT INTO validators (pubkey_hash, pubkey, self_stake,"
            " total_delegated, external_delegated, commission_bps,"
            " pending_commission_bps, pending_effective_block, status,"
            " active_since_block, unstake_commit_block,"
            " unstake_destination_fp, unstake_destination_pubkey,"
            " last_validator_update_block, consecutive_missed_epochs,"
            " last_signed_block, signed_blocks_this_epoch)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            -1, &stmt, NULL) != SQLITE_OK) return -1;

        sqlite3_bind_blob (stmt,  1, pubkey_hash, 64, SQLITE_STATIC);
        sqlite3_bind_blob (stmt,  2, pubkey, DNAC_PUBKEY_SIZE, SQLITE_STATIC);
        sqlite3_bind_int64(stmt,  3, (sqlite3_int64)(10000000 * i));
        sqlite3_bind_int64(stmt,  4, (sqlite3_int64)(500 * i));
        sqlite3_bind_int64(stmt,  5, (sqlite3_int64)(300 * i));
        sqlite3_bind_int  (stmt,  6, 100 * i);
        sqlite3_bind_int  (stmt,  7, 10 * i);
        sqlite3_bind_int64(stmt,  8, (sqlite3_int64)(1000 + i));
        sqlite3_bind_int  (stmt,  9, 1);                 /* status ACTIVE */
        sqlite3_bind_int64(stmt, 10, (sqlite3_int64)(5 * i));
        sqlite3_bind_int64(stmt, 11, 0);
        sqlite3_bind_text (stmt, 12, fp, 128, SQLITE_STATIC);
        sqlite3_bind_blob (stmt, 13, upk, DNAC_PUBKEY_SIZE, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 14, (sqlite3_int64)(20 + i));
        sqlite3_bind_int64(stmt, 15, (sqlite3_int64)i);
        sqlite3_bind_int64(stmt, 16, (sqlite3_int64)(900 + i));
        sqlite3_bind_int64(stmt, 17, (sqlite3_int64)(30 + i));

        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) return -1;
    }
    return 0;
}

/* 2 delegation rows, distinct in BOTH sort keys. */
static int insert_delegations(nodus_witness_t *w) {
    for (int i = 1; i <= 2; i++) {
        uint8_t dhash[64], vhash[64];
        uint8_t dpk[DNAC_PUBKEY_SIZE], vpk[DNAC_PUBKEY_SIZE];
        memset(dhash, (uint8_t)(0x60 + i), sizeof(dhash));
        memset(vhash, (uint8_t)(0x70 + i), sizeof(vhash));
        /* ⚠ DE-CORRELATED ON PURPOSE (O6 finding). The production ORDER BY is
         * `validator_pubkey, delegator_pubkey` (nodus_witness_merkle.c:1130).
         * If both keys ascended with `i`, sorting by (v,d) and by (d,v) would
         * yield the SAME row order, and a swap of the two sort keys would be
         * invisible to this golden. So delegator DESCENDS while validator
         * ASCENDS: by (v,d) the rows come out 1,2; by (d,v) they come out 2,1. */
        memset(dpk,   (uint8_t)(0x80 + (3 - i)), sizeof(dpk)); /* 2 rows: 0x82, 0x81 */
        memset(vpk,   (uint8_t)(0x90 + i), sizeof(vpk));

        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(w->db,
            "INSERT INTO delegations (delegator_hash, validator_hash,"
            " delegator_pubkey, validator_pubkey, amount,"
            " delegated_at_block) VALUES (?, ?, ?, ?, ?, ?)",
            -1, &stmt, NULL) != SQLITE_OK) return -1;
        sqlite3_bind_blob (stmt, 1, dhash, 64, SQLITE_STATIC);
        sqlite3_bind_blob (stmt, 2, vhash, 64, SQLITE_STATIC);
        sqlite3_bind_blob (stmt, 3, dpk, DNAC_PUBKEY_SIZE, SQLITE_STATIC);
        sqlite3_bind_blob (stmt, 4, vpk, DNAC_PUBKEY_SIZE, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 5, (sqlite3_int64)(250000 * i));
        sqlite3_bind_int64(stmt, 6, (sqlite3_int64)(40 + i));
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) return -1;
    }
    return 0;
}

/* 2 epoch_state rows.
 *
 * ⚠ HONEST LABEL: production keeps at most ONE active epoch_state row
 * (nodus_witness.c:178-180). Two rows is a legal shape for the loader
 * and strictly WIDENS what the pin covers — it exercises the two-leaf
 * RFC 6962 reduction for this subtree instead of the single-leaf
 * shortcut — but it is not the shape a live chain holds. The per-row
 * leaf encoding, which is what a format change would move, is identical
 * either way. */
static int insert_epoch_state(nodus_witness_t *w) {
    for (int i = 1; i <= 2; i++) {
        uint8_t snap[64];
        memset(snap, (uint8_t)(0xb0 + i), sizeof(snap));

        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(w->db,
            "INSERT INTO epoch_state (epoch_start_height, epoch_pool_accum,"
            " snapshot_hash) VALUES (?, ?, ?)",
            -1, &stmt, NULL) != SQLITE_OK) return -1;
        sqlite3_bind_int64(stmt, 1, (sqlite3_int64)(100 * i));
        sqlite3_bind_int64(stmt, 2, (sqlite3_int64)(4242 * i));
        sqlite3_bind_blob (stmt, 3, snap, 64, SQLITE_STATIC);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) return -1;
    }
    return 0;
}

/* The single supply_tracking row.
 *
 * Deliberately PRESENT rather than absent. An absent row is the
 * pre-genesis state and both builds treat it the same way (zeroed
 * counters), but "present with fixed non-zero counters" is what a live
 * chain has, and it also makes total_minted / total_burned real inputs
 * to the pin instead of constants that happen to be zero. */
static int insert_supply(nodus_witness_t *w) {
    uint8_t last_tx_hash[64];
    memset(last_tx_hash, 0xc1, sizeof(last_tx_hash));

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(w->db,
        "INSERT INTO supply_tracking (id, genesis_supply, total_burned,"
        " total_minted, current_supply, last_tx_hash, last_sequence)"
        " VALUES (1, ?, ?, ?, ?, ?, ?)", -1, &stmt, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)100000000000000LL);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)12345);
    sqlite3_bind_int64(stmt, 3, (sqlite3_int64)67890);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)99999999999999LL);
    sqlite3_bind_blob (stmt, 5, last_tx_hash, 64, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)77);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* 3 chain_config_history rows. Distinct effective_block values give the
 * four-key ORDER BY a total order on its FIRST key alone, so the pin
 * does not depend on how the planner breaks ties.
 *
 * created_at_unix is NOT read by nodus_chain_config_compute_root
 * (:317-322 selects five columns and this is not one of them), but the
 * column is NOT NULL, so it is bound to a FIXED 0 — never time(NULL),
 * which would make the fixture non-reproducible even though the value
 * is not hashed. */
static int insert_chain_config(nodus_witness_t *w) {
    for (int i = 1; i <= 3; i++) {
        uint8_t tx_hash[64];
        memset(tx_hash, (uint8_t)(0xd0 + i), sizeof(tx_hash));

        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(w->db,
            "INSERT INTO chain_config_history (param_id, new_value,"
            " effective_block, commit_block, tx_hash, proposal_nonce,"
            " created_at_unix) VALUES (?, ?, ?, ?, ?, ?, 0)",
            -1, &stmt, NULL) != SQLITE_OK) return -1;
        /* ⚠ DE-CORRELATED ON PURPOSE (O6 finding). The production ORDER BY is
         * `effective_block, param_id, commit_block, proposal_nonce`
         * (nodus_witness_chain_config.c:321-322). If all four ascended with
         * `i`, ANY permutation of the four sort keys would produce the same
         * row order and be invisible to this golden. So the PRIMARY key
         * ascends and the other three DESCEND: ordering by effective_block
         * gives 1,2,3, while ordering by any of the others gives 3,2,1. */
        sqlite3_bind_int  (stmt, 1, 3 - i);                     /* param_id  2,1,0 */
        sqlite3_bind_int64(stmt, 2, (sqlite3_int64)(500 * i));
        sqlite3_bind_int64(stmt, 3, (sqlite3_int64)(10 * i));   /* effective 10,20,30 */
        sqlite3_bind_int64(stmt, 4, (sqlite3_int64)(10 * (4 - i) - 5)); /* commit 25,15,5 */
        sqlite3_bind_blob (stmt, 5, tx_hash, 64, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 6, (sqlite3_int64)(7 * (4 - i)));      /* nonce 21,14,7 */
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) return -1;
    }
    return 0;
}

/* Build the complete fixture. Returns a witness or NULL. */
static nodus_witness_t *golden_fixture(void) {
    nodus_witness_t *w = witness_new();
    if (!w) return NULL;
    if (create_schema(w)        != 0) goto fail;
    if (insert_utxos(w)         != 0) goto fail;
    if (insert_validators(w)    != 0) goto fail;
    if (insert_delegations(w)   != 0) goto fail;
    if (insert_epoch_state(w)   != 0) goto fail;
    if (insert_supply(w)        != 0) goto fail;
    if (insert_chain_config(w)  != 0) goto fail;
    return w;
fail:
    witness_free(w);
    return NULL;
}

/* ── Tests ─────────────────────────────────────────────────────────── */

static void test_golden_state_root(void) {
    TEST("state_root matches the pinned golden vector");

    if (golden_is_unfilled()) {
        FAIL("GOLDEN_STATE_ROOT is the all-zero PLACEHOLDER — the pin has "
             "not been filled yet.\n"
             "        Fail-close by design: an unfilled pin must never "
             "report a green cross-version check.\n"
             "        Fill it with: ./test_merkle_state_root_golden "
             "--print-root  (run against the PRE-deploy commit)");
        return;
    }

    nodus_witness_t *w = golden_fixture();
    if (!w) { FAIL("fixture"); return; }

    uint8_t root[64];
    /* O15J Faz 3 — the state_root v4 (6-leg) composition is gone with the
     * activation ceremony that was its only reason to exist. Production is
     * and stays v3 over the five real subtrees, which is the composition
     * GOLDEN_STATE_ROOT has always pinned; the golden VALUE is untouched by
     * that removal. */
    if (nodus_witness_merkle_compute_state_root(w, root) != 0) {
        FAIL("compute_state_root returned -1");
        witness_free(w);
        return;
    }

    if (memcmp(root, GOLDEN_STATE_ROOT, 64) != 0) {
        printf("FAIL: state_root DIVERGED from the pin\n");
        printf("        expected: ");
        for (int i = 0; i < 64; i++) printf("%02x", GOLDEN_STATE_ROOT[i]);
        printf("\n        actual:   ");
        for (int i = 0; i < 64; i++) printf("%02x", root[i]);
        printf("\n        The state_root composition changed. A node on the "
               "old build and a node\n"
               "        on this build will NOT agree on state_root for the "
               "same state.\n");
        failed++;
        witness_free(w);
        return;
    }

    PASS();
    witness_free(w);
}

/* Same fixture built twice from scratch must give the same root. This is
 * the RELATIONAL property test_merkle_utxo_root.c already covers for the
 * utxo subtree, extended to the full five-input composition. It is a
 * weaker claim than the pin and is here to separate "the pin moved"
 * from "the computation is not even stable within one build". */
static void test_state_root_stable_within_build(void) {
    TEST("state_root stable across two identical fixtures");

    nodus_witness_t *w1 = golden_fixture();
    if (!w1) { FAIL("fixture 1"); return; }
    nodus_witness_t *w2 = golden_fixture();
    if (!w2) { FAIL("fixture 2"); witness_free(w1); return; }

    uint8_t r1[64], r2[64];
    if (nodus_witness_merkle_compute_state_root(w1, r1) != 0) {
        FAIL("compute 1"); goto done;
    }
    if (nodus_witness_merkle_compute_state_root(w2, r2) != 0) {
        FAIL("compute 2"); goto done;
    }
    if (memcmp(r1, r2, 64) != 0) { FAIL("roots differ"); goto done; }

    PASS();
done:
    witness_free(w1);
    witness_free(w2);
}

/* Non-vacuity: `mutation` must move the root. If it does not, the table
 * it touches contributes NOTHING to state_root and the pin is blind to
 * it — which is exactly the failure mode a golden vector exists to
 * prevent. */
static void test_input_contributes(const char *label, const char *mutation) {
    TEST(label);

    nodus_witness_t *base = golden_fixture();
    if (!base) { FAIL("fixture base"); return; }
    nodus_witness_t *mut = golden_fixture();
    if (!mut) { FAIL("fixture mutated"); witness_free(base); return; }

    if (exec_sql(mut, mutation) != 0) { FAIL("mutation sql"); goto done; }

    /* A WHERE clause that matches nothing is an SQLITE_OK no-op, and the
     * root would then be "unchanged" for a reason that has nothing to do
     * with the property under test. Fail on it explicitly so the message
     * says "broken fixture", not "input does not reach state_root". */
    if (sqlite3_changes(mut->db) == 0) {
        FAIL("mutation matched 0 rows — fixture and WHERE clause disagree");
        goto done;
    }

    uint8_t r0[64], r1[64];
    if (nodus_witness_merkle_compute_state_root(base, r0) != 0) {
        FAIL("compute base"); goto done;
    }
    if (nodus_witness_merkle_compute_state_root(mut, r1) != 0) {
        FAIL("compute mutated"); goto done;
    }
    if (memcmp(r0, r1, 64) == 0) {
        FAIL("root UNCHANGED — this input does not reach state_root");
        goto done;
    }

    PASS();
done:
    witness_free(base);
    witness_free(mut);
}

/* ── --print-root ──────────────────────────────────────────────────── */

static int print_root(void) {
    nodus_witness_t *w = golden_fixture();
    if (!w) {
        fprintf(stderr, "print-root: fixture build failed\n");
        return 1;
    }

    uint8_t root[64];
    if (nodus_witness_merkle_compute_state_root(w, root) != 0) {
        fprintf(stderr, "print-root: compute_state_root returned -1\n");
        witness_free(w);
        return 1;
    }
    witness_free(w);

    printf("static const uint8_t GOLDEN_STATE_ROOT[64] = {\n");
    for (int i = 0; i < 64; i += 8) {
        printf("   ");
        for (int j = 0; j < 8; j++) printf(" 0x%02x,", root[i + j]);
        printf("\n");
    }
    printf("};\n");
    return 0;
}

/* ── main ──────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--print-root") == 0)
        return print_root();

    printf("\nNodus state_root GOLDEN VECTOR\n");
    printf("==========================================\n\n");

    test_state_root_stable_within_build();

    /* One mutation per state_root input. `WHERE` clauses target values,
     * never rowids that depend on insertion order. */
    test_input_contributes(
        "utxo_set reaches state_root",
        "UPDATE utxo_set SET amount = amount + 1 WHERE output_index = 2;");
    test_input_contributes(
        "validators reaches state_root",
        "UPDATE validators SET self_stake = self_stake + 1 "
        "WHERE commission_bps = 200;");
    test_input_contributes(
        "delegations reaches state_root",
        "UPDATE delegations SET amount = amount + 1 "
        "WHERE delegated_at_block = 41;");
    test_input_contributes(
        "epoch_state reaches state_root",
        "UPDATE epoch_state SET epoch_pool_accum = epoch_pool_accum + 1 "
        "WHERE epoch_start_height = 100;");
    test_input_contributes(
        "chain_config_history reaches state_root",
        "UPDATE chain_config_history SET new_value = new_value + 1 "
        "WHERE param_id = 0;");
    test_input_contributes(
        "supply_tracking reaches state_root (via epoch_state leaves)",
        "UPDATE supply_tracking SET total_minted = total_minted + 1 "
        "WHERE id = 1;");

    test_golden_state_root();

    printf("\n==========================================\n");
    printf("Results: %d passed, %d failed\n\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
