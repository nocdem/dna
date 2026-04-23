/**
 * Nodus — "My Delegations" query test
 *
 * Exercises the DB layer that backs the new dnac_delegations T3 RPC:
 * nodus_delegation_insert + nodus_delegation_list_by_delegator. These
 * are used unchanged from the existing stake-delegation feature; the
 * T3 handler is a thin wrapper that C11-authenticates the caller and
 * forwards the query. Handler-level auth test is deferred to the P2
 * SDK round-trip suite (needs TCP conn scaffolding).
 *
 * Tests:
 *   1. empty table → count == 0
 *   2. one seeded row → count == 1, fields match
 *   3. query with unrelated delegator pubkey → count == 0
 *   4. two rows same delegator → count == 2
 *   5. row for a different delegator does not leak into our result
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_delegation.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>

#define TEST(name) do { printf("  %-55s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

static int run_ddl(sqlite3 *db, const char *ddl) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, ddl, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

static int setup(nodus_witness_t *w) {
    memset(w, 0, sizeof(*w));
    if (sqlite3_open(":memory:", &w->db) != SQLITE_OK) return -1;

    const char *statements[] = {
        "CREATE TABLE delegations ("
        "  delegator_hash BLOB,"
        "  validator_hash BLOB,"
        "  delegator_pubkey BLOB NOT NULL,"
        "  validator_pubkey BLOB NOT NULL,"
        "  amount INTEGER NOT NULL,"
        "  delegated_at_block INTEGER NOT NULL,"
        "  PRIMARY KEY (delegator_hash, validator_hash)"
        ")",
        "CREATE INDEX idx_delegator ON delegations (delegator_hash)",
        "CREATE INDEX idx_validator ON delegations (validator_hash)",
        NULL
    };

    for (int i = 0; statements[i]; i++) {
        if (run_ddl(w->db, statements[i]) != 0) {
            fprintf(stderr, "ddl failed at step %d\n", i);
            sqlite3_close(w->db);
            return -1;
        }
    }
    return 0;
}

/* Fill a pubkey BLOB with a repeating byte marker so each seeded row
 * is deterministically distinguishable without touching real Dilithium5
 * keys. The DB columns only care about byte-identity for PK hashing. */
static void fill_pubkey(uint8_t *buf, uint8_t marker) {
    memset(buf, marker, DNAC_PUBKEY_SIZE);
}

static int seed_row(nodus_witness_t *w, uint8_t del_marker,
                    uint8_t val_marker, uint64_t amount, uint64_t block) {
    dnac_delegation_record_t r;
    memset(&r, 0, sizeof(r));
    fill_pubkey(r.delegator_pubkey, del_marker);
    fill_pubkey(r.validator_pubkey, val_marker);
    r.amount = amount;
    r.delegated_at_block = block;
    return nodus_delegation_insert(w, &r);
}

static void test_empty_returns_zero(void) {
    TEST("empty table -> count 0");
    nodus_witness_t w;
    if (setup(&w) != 0) { FAIL("setup"); return; }

    uint8_t pubkey[DNAC_PUBKEY_SIZE];
    fill_pubkey(pubkey, 0x11);

    dnac_delegation_record_t out[8];
    int count = -1;
    int rc = nodus_delegation_list_by_delegator(&w, pubkey, out, 8, &count);

    if (rc != 0)      { FAIL("rc");    goto done; }
    if (count != 0)   { FAIL("count"); goto done; }
    PASS();
done:
    sqlite3_close(w.db);
}

static void test_one_row_round_trip(void) {
    TEST("one row seeded -> count 1, fields match");
    nodus_witness_t w;
    if (setup(&w) != 0) { FAIL("setup"); return; }

    if (seed_row(&w, 0xAA, 0xBB, 1234567890ULL, 42) != 0) {
        FAIL("seed"); sqlite3_close(w.db); return;
    }

    uint8_t del_pubkey[DNAC_PUBKEY_SIZE];
    fill_pubkey(del_pubkey, 0xAA);

    dnac_delegation_record_t out[8];
    int count = 0;
    if (nodus_delegation_list_by_delegator(&w, del_pubkey, out, 8, &count) != 0) {
        FAIL("list rc"); sqlite3_close(w.db); return;
    }
    if (count != 1)                           { FAIL("count"); goto done; }
    if (out[0].amount != 1234567890ULL)        { FAIL("amount"); goto done; }
    if (out[0].delegated_at_block != 42)       { FAIL("block"); goto done; }
    if (out[0].validator_pubkey[0] != 0xBB)    { FAIL("validator pk"); goto done; }
    if (out[0].delegator_pubkey[0] != 0xAA)    { FAIL("delegator pk"); goto done; }
    PASS();
done:
    sqlite3_close(w.db);
}

static void test_unrelated_delegator_empty(void) {
    TEST("query with unrelated pubkey -> count 0");
    nodus_witness_t w;
    if (setup(&w) != 0) { FAIL("setup"); return; }

    if (seed_row(&w, 0xAA, 0xBB, 100, 1) != 0) {
        FAIL("seed"); sqlite3_close(w.db); return;
    }

    uint8_t other_pubkey[DNAC_PUBKEY_SIZE];
    fill_pubkey(other_pubkey, 0xCC);  /* different marker */

    dnac_delegation_record_t out[8];
    int count = -1;
    if (nodus_delegation_list_by_delegator(&w, other_pubkey, out, 8, &count) != 0) {
        FAIL("list rc"); sqlite3_close(w.db); return;
    }
    if (count != 0) { FAIL("count"); goto done; }
    PASS();
done:
    sqlite3_close(w.db);
}

static void test_two_rows_same_delegator(void) {
    TEST("two rows same delegator -> count 2");
    nodus_witness_t w;
    if (setup(&w) != 0) { FAIL("setup"); return; }

    if (seed_row(&w, 0xAA, 0xB1, 100, 1) != 0) {
        FAIL("seed 1"); sqlite3_close(w.db); return;
    }
    if (seed_row(&w, 0xAA, 0xB2, 200, 2) != 0) {
        FAIL("seed 2"); sqlite3_close(w.db); return;
    }

    uint8_t del_pubkey[DNAC_PUBKEY_SIZE];
    fill_pubkey(del_pubkey, 0xAA);

    dnac_delegation_record_t out[8];
    int count = 0;
    if (nodus_delegation_list_by_delegator(&w, del_pubkey, out, 8, &count) != 0) {
        FAIL("list rc"); sqlite3_close(w.db); return;
    }
    if (count != 2) { FAIL("count"); goto done; }
    PASS();
done:
    sqlite3_close(w.db);
}

static void test_other_delegator_not_leaked(void) {
    TEST("other delegator row excluded from our result");
    nodus_witness_t w;
    if (setup(&w) != 0) { FAIL("setup"); return; }

    /* Two delegators, three rows total. Our query must see only its own. */
    if (seed_row(&w, 0xAA, 0xB1, 100, 1) != 0) { FAIL("seed 1"); goto done; }
    if (seed_row(&w, 0xAA, 0xB2, 200, 2) != 0) { FAIL("seed 2"); goto done; }
    if (seed_row(&w, 0xCC, 0xB1, 999, 3) != 0) { FAIL("seed 3"); goto done; }

    uint8_t del_pubkey[DNAC_PUBKEY_SIZE];
    fill_pubkey(del_pubkey, 0xAA);

    dnac_delegation_record_t out[8];
    int count = 0;
    if (nodus_delegation_list_by_delegator(&w, del_pubkey, out, 8, &count) != 0) {
        FAIL("list rc"); goto done;
    }
    if (count != 2) { FAIL("count leak"); goto done; }
    /* Verify no row has the 0xCC delegator marker */
    for (int i = 0; i < count; i++) {
        if (out[i].delegator_pubkey[0] == 0xCC) {
            FAIL("0xCC leaked"); goto done;
        }
    }
    PASS();
done:
    sqlite3_close(w.db);
}

int main(void) {
    printf("witness_delegations_query tests\n");
    printf("===============================\n");

    test_empty_returns_zero();
    test_one_row_round_trip();
    test_unrelated_delegator_empty();
    test_two_rows_same_delegator();
    test_other_delegator_not_leaked();

    printf("\nPassed: %d\nFailed: %d\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
