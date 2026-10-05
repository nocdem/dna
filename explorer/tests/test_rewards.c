/* Offline rewards regressions. Disposable SQLite fixtures only; no node,
 * network, keys or backfill. See explorer/README.md for prerequisites. */
#include "exp_http.h"
#include "exp_rewards.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    char source_path[80];
    char index_path[80];
    sqlite3 *source;
    exp_db_t *index;
    exp_http_ctx_t ctx;
} fixture_t;

static int failures;
#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #c); \
    failures++; goto done; } } while (0)

static int sql(sqlite3 *db, const char *query) {
    char *err = NULL;
    int rc = sqlite3_exec(db, query, NULL, NULL, &err);
    if (rc != SQLITE_OK) fprintf(stderr, "fixture SQL: %s\n", err ? err : "failed");
    sqlite3_free(err);
    return rc == SQLITE_OK ? 0 : -1;
}

static void remove_db(const char *path) {
    if (!*path) return;
    char side[96];
    unlink(path);
    snprintf(side, sizeof(side), "%s-wal", path); unlink(side);
    snprintf(side, sizeof(side), "%s-shm", path); unlink(side);
}

static void fixture_close(fixture_t *f) {
    exp_db_close(f->index);
    sqlite3_close(f->source);
    remove_db(f->source_path);
    remove_db(f->index_path);
}

static int fixture_open(fixture_t *f) {
    memset(f, 0, sizeof(*f));
    strcpy(f->source_path, "/tmp/exp_rewards_source_XXXXXX");
    strcpy(f->index_path, "/tmp/exp_rewards_index_XXXXXX");
    int fd = mkstemp(f->source_path);
    if (fd < 0) return -1;
    close(fd);
    fd = mkstemp(f->index_path);
    if (fd < 0) return -1;
    close(fd);
    if (sqlite3_open(f->source_path, &f->source) != SQLITE_OK ||
        exp_db_open(f->index_path, &f->index) != 0) return -1;
    if (sql(f->source,
            "PRAGMA journal_mode=WAL;"
            "CREATE TABLE v2_blocks(global_height INTEGER PRIMARY KEY,block_id BLOB);"
            "CREATE TABLE addr_history(h INTEGER,i INTEGER,seq INTEGER,owner BLOB,"
            "kind TEXT,amount INTEGER,token BLOB,ts INTEGER,PRIMARY KEY(h,i,seq));"
            "CREATE INDEX idx_addr_history_owner ON addr_history(owner,h,i,seq);"
            "CREATE TABLE addr_history_mark(id INTEGER PRIMARY KEY,from_height INTEGER,last_height INTEGER);"
            "CREATE TABLE v2_reward_accrual(owner_fp BLOB PRIMARY KEY,amount INTEGER);"
            "INSERT INTO v2_blocks VALUES(17280,zeroblob(64)),(34560,zeroblob(64)),"
            "(51840,zeroblob(64)),(51850,zeroblob(64));"
            "INSERT INTO addr_history_mark VALUES(1,20000,51850);") != 0) return -1;

    sqlite3 *index = NULL;
    if (sqlite3_open(f->index_path, &index) != SQLITE_OK) {
        sqlite3_close(index); return -1;
    }
    /* The router needs these three headers only. Sparse synthetic index:
     * this is not a sync/verify-index fixture and never claimed as one. */
    int rc = sql(index,
            "INSERT INTO blocks VALUES(17280,zeroblob(64),zeroblob(64),17280000,zeroblob(32),zeroblob(64),0,0),"
            "(34560,zeroblob(64),zeroblob(64),34560000,zeroblob(32),zeroblob(64),0,0),"
            "(51840,zeroblob(64),zeroblob(64),51840000,zeroblob(32),zeroblob(64),0,0);");
    sqlite3_close(index);
    if (rc != 0) return -1;
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(f->source,
            "INSERT INTO addr_history VALUES(34560,4294967295,?1,?2,'payout',?3,zeroblob(64),34560)",
            -1, &s, NULL) != SQLITE_OK) return -1;
    for (int i = 0; i < 101; i++) {
        uint8_t owner[64];
        memset(owner, i < 2 ? 0xaa : 0xbb, sizeof(owner));
        if (i >= 2) owner[63] = (uint8_t)i;
        sqlite3_bind_int(s, 1, i * 2); /* release rows can occupy the gaps */
        sqlite3_bind_blob(s, 2, owner, sizeof(owner), SQLITE_TRANSIENT);
        sqlite3_bind_int64(s, 3, i == 0 ? INT64_C(9007199254740993) : i == 1 ? 10 : 1);
        rc = sqlite3_step(s);
        sqlite3_reset(s);
        if (rc != SQLITE_DONE) { sqlite3_finalize(s); return -1; }
    }
    sqlite3_finalize(s);
    if (sql(f->source,
            "INSERT INTO addr_history SELECT 17280,4294967295,0,owner,'payout',7,token,17280 "
            "FROM addr_history WHERE h=34560 AND seq=0;"
            "INSERT INTO addr_history SELECT 34560,4294967295,1,owner,'release',999,token,34560 "
            "FROM addr_history WHERE h=34560 AND seq=0;"
            "INSERT INTO v2_reward_accrual SELECT owner,23 FROM addr_history WHERE h=34560 AND seq=0;") != 0)
        return -1;
    f->ctx.db = &f->index;
    f->ctx.rewards_db_path = f->source_path;
    return 0;
}

static int expect(fixture_t *f, const char *path, int expected,
                   const char *a, const char *b, const char *c) {
    exp_json_t body;
    int status = 0;
    int rc = exp_http_route(&f->ctx, "GET", path, &body, &status);
    int ok = rc == 0 && status == expected && body.buf &&
             (!a || strstr(body.buf, a)) && (!b || strstr(body.buf, b)) &&
             (!c || strstr(body.buf, c));
    if (!ok) fprintf(stderr, "%s: want %d; got %d: %s\n", path, expected,
                     status, body.buf ? body.buf : "(null)");
    exp_json_freebuf(&body);
    return ok;
}

static void address_path(char out[256], char owner_digit, const char *suffix) {
    strcpy(out, "/api/rewards/");
    memset(out + 13, owner_digit, 128);
    strcpy(out + 141, suffix);
}

static void test_rewards_routes(void) {
    fixture_t f;
    char path[256];
    CHECK(fixture_open(&f) == 0);
    CHECK(expect(&f, "/api/paydays?limit=2", 200, "\"from_height\":20000,\"at_height\":51840",
                 "\"height\":51840,\"time\":51840000,\"total\":\"0\",\"recipients\":0,\"available\":true",
                 "\"next_before\":34560"));
    CHECK(expect(&f, "/api/paydays?before=34560", 200,
                 "\"height\":17280,\"time\":17280000,\"total\":null,\"recipients\":null,\"available\":false",
                 "\"next_before\":null", NULL));
    CHECK(expect(&f, "/api/payday/34560", 200, "\"total\":\"9007199254741102\",\"recipients\":101",
                 "\"amount\":\"9007199254740993\",\"sequence\":0", "\"next_from\":200"));
    CHECK(expect(&f, "/api/payday/34560?from=200", 200,
                 "\"amount\":\"1\",\"sequence\":200", "\"next_from\":null", NULL));
    CHECK(expect(&f, "/api/payday/34560?from=1&limit=1", 200,
                 "\"amount\":\"10\",\"sequence\":2", "\"next_from\":4", NULL));
    address_path(path, 'a', "?limit=1");
    CHECK(expect(&f, path, 200, "\"at_height\":51850,\"paid_total\":\"9007199254741003\",\"pending\":\"23\"",
                 "\"amount\":\"10\",\"sequence\":2", "\"next_before\":\"34560:2\""));
    address_path(path, 'a', "?before=34560:2&limit=1");
    CHECK(expect(&f, path, 200, "\"time\":34560000,\"amount\":\"9007199254740993\",\"sequence\":0",
                 "\"next_before\":null", "\"paid_total\":\"9007199254741003\""));
    address_path(path, 'c', "");
    CHECK(expect(&f, path, 200, "\"paid_total\":\"0\",\"pending\":\"0\",\"items\":[]", NULL, NULL));
    CHECK(expect(&f, "/api/payday/17280", 503, "rewards unavailable", NULL, NULL));
    CHECK(expect(&f, "/api/payday/69120", 503, NULL, NULL, NULL));
done:
    fixture_close(&f);
}

static void test_rewards_invalid_requests(void) {
    fixture_t f;
    CHECK(fixture_open(&f) == 0);
    const char *bad[] = {"/api/payday/7", "/api/payday/0", "/api/payday/34560?from=4294967296",
        "/api/payday/34560?from=-1", "/api/paydays?before=0", "/api/paydays?limit=0",
        "/api/paydays?limit=1&limit=2", "/api/paydays?before=9223372036854775808",
        "/api/paydays?before=000000000000000000000000000000000000000000000000001bad",
        "/api/rewards/aa", "/api/payday/34560?from=1x"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        CHECK(expect(&f, bad[i], 400, NULL, NULL, NULL));
done:
    fixture_close(&f);
}

static void test_rewards_source_faults(void) {
    fixture_t f;
    char path[256];
    CHECK(fixture_open(&f) == 0);
    f.ctx.rewards_db_path = NULL;
    CHECK(expect(&f, "/api/paydays", 503, NULL, NULL, NULL));
    CHECK(expect(&f, "/api/stats", 200, NULL, NULL, NULL));
    f.ctx.rewards_db_path = "/dev/null/absent-rewards.db";
    CHECK(expect(&f, "/api/paydays", 503, NULL, NULL, NULL));
    f.ctx.rewards_db_path = f.source_path;
    CHECK(sql(f.source, "UPDATE v2_blocks SET block_id=zeroblob(63) WHERE global_height=51840") == 0);
    CHECK(expect(&f, "/api/paydays", 503, NULL, NULL, NULL));
    CHECK(sql(f.source, "UPDATE v2_blocks SET block_id=CAST(x'01'||zeroblob(63) AS BLOB) WHERE global_height=51840") == 0);
    CHECK(expect(&f, "/api/paydays", 503, NULL, NULL, NULL));
    CHECK(sql(f.source, "UPDATE v2_blocks SET block_id=zeroblob(64) WHERE global_height=51840;"
                        "UPDATE addr_history_mark SET last_height=51840") == 0);
    CHECK(expect(&f, "/api/paydays", 503, NULL, NULL, NULL));
    CHECK(sql(f.source, "UPDATE addr_history_mark SET last_height=51850,from_height=51851") == 0);
    CHECK(expect(&f, "/api/paydays", 503, NULL, NULL, NULL));
    CHECK(sql(f.source, "UPDATE addr_history_mark SET from_height=20000;"
                        "UPDATE addr_history SET amount=-1 WHERE h=34560 AND seq=0") == 0);
    CHECK(expect(&f, "/api/payday/34560", 503, NULL, NULL, NULL));
    CHECK(sql(f.source, "UPDATE addr_history SET amount=1,ts=NULL WHERE h=34560 AND seq=0") == 0);
    CHECK(expect(&f, "/api/payday/34560", 503, NULL, NULL, NULL));
    CHECK(sql(f.source, "UPDATE addr_history SET ts=9223372036854775807 WHERE h=34560 AND seq=0") == 0);
    CHECK(expect(&f, "/api/payday/34560", 503, NULL, NULL, NULL));
    CHECK(sql(f.source, "UPDATE addr_history SET ts=34560,token=zeroblob(63) WHERE h=34560 AND seq=0") == 0);
    CHECK(expect(&f, "/api/payday/34560", 503, NULL, NULL, NULL));
    CHECK(sql(f.source, "UPDATE addr_history SET token=CAST(x'01'||zeroblob(63) AS BLOB) WHERE h=34560 AND seq=0") == 0);
    CHECK(expect(&f, "/api/payday/34560", 503, NULL, NULL, NULL));
    CHECK(sql(f.source, "UPDATE addr_history SET token=zeroblob(64),amount=9223372036854775807 WHERE h=34560 AND kind='payout'") == 0);
    CHECK(expect(&f, "/api/payday/34560", 503, NULL, NULL, NULL));
    CHECK(sql(f.source, "UPDATE addr_history SET token=zeroblob(64) WHERE h=34560 AND seq=0;"
                        "UPDATE addr_history SET amount=1 WHERE h=34560;"
                        "UPDATE v2_reward_accrual SET amount='corrupt'") == 0);
    address_path(path, 'a', "");
    CHECK(expect(&f, path, 503, NULL, NULL, NULL));
    CHECK(sql(f.source, "DELETE FROM addr_history_mark") == 0);
    CHECK(expect(&f, "/api/paydays", 503, NULL, NULL, NULL));
    CHECK(sql(f.source, "INSERT INTO addr_history_mark VALUES(1,20000,51850)") == 0);
    CHECK(sql(f.source, "DROP TABLE addr_history") == 0);
    CHECK(expect(&f, "/api/payday/34560", 503, NULL, NULL, NULL));
    CHECK(expect(&f, "/api/stats", 200, NULL, NULL, NULL));
done:
    fixture_close(&f);
}

static int data_version(sqlite3 *db) {
    sqlite3_stmt *s = NULL;
    int v = -1;
    if (sqlite3_prepare_v2(db, "PRAGMA data_version", -1, &s, NULL) == SQLITE_OK &&
        sqlite3_step(s) == SQLITE_ROW) v = sqlite3_column_int(s, 0);
    sqlite3_finalize(s);
    return v;
}

static void test_rewards_snapshot_and_readonly(void) {
    fixture_t f;
    exp_rewards_t *r = NULL;
    exp_rewards_page_t page;
    exp_block_row_t anchor;
    uint8_t owner[64]; memset(owner, 0xaa, sizeof(owner));
    CHECK(fixture_open(&f) == 0);
    int before = data_version(f.source);
    CHECK(before >= 0);
    CHECK(expect(&f, "/api/payday/34560?limit=1", 200, NULL, NULL, NULL));
    CHECK(data_version(f.source) == before); /* no external connection wrote */
    CHECK(exp_db_query_block_by_height(f.index, 51840, &anchor) == 0);
    CHECK(exp_rewards_open(f.source_path, &anchor, &r) == 0);
    CHECK(sql(f.source, "UPDATE v2_reward_accrual SET amount=99") == 0);
    CHECK(exp_rewards_address(r, owner, 0, 0, 25, &page) == 0 && page.pending == 23);
    exp_rewards_close(r); r = NULL;
    CHECK(exp_rewards_open(f.source_path, &anchor, &r) == 0);
    CHECK(exp_rewards_address(r, owner, 0, 0, 25, &page) == 0 && page.pending == 99);
    exp_rewards_close(r); r = NULL;
    CHECK(sql(f.source, "DELETE FROM v2_blocks WHERE global_height>=51840") == 0);
    CHECK(exp_rewards_open(f.source_path, &anchor, &r) != 0 && !r);
done:
    exp_rewards_close(r);
    fixture_close(&f);
}

static void test_rewards_work_budget(void) {
    fixture_t f;
    CHECK(fixture_open(&f) == 0);
    /* All rows sit in one indexed height. Even a valid large source must
     * fail honestly when its total cannot be computed within the budget. */
    CHECK(sql(f.source,
        "WITH RECURSIVE n(x) AS (VALUES(1000) UNION ALL SELECT x+1 FROM n WHERE x<301000) "
        "INSERT INTO addr_history SELECT 34560,4294967295,x,zeroblob(64),'payout',1,zeroblob(64),34560 FROM n") == 0);
    CHECK(expect(&f, "/api/payday/34560?limit=1", 503, "rewards unavailable", NULL, NULL));
    CHECK(expect(&f, "/api/stats", 200, NULL, NULL, NULL));
done:
    fixture_close(&f);
}

int main(void) {
    test_rewards_routes();
    test_rewards_invalid_requests();
    test_rewards_source_faults();
    test_rewards_snapshot_and_readonly();
    test_rewards_work_budget();
    printf("Rewards regression groups: 5; failures: %d\n", failures);
    return failures ? 1 : 0;
}
