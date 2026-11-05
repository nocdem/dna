/**
 * @file nodus/tests/test_hf9_growth.c
 * @brief HF-9 WP4, plan row T-9 (the storage-assignment part) - the growth
 *        rule: per-boundary work grows only with the records the boundary
 *        changes, never with the history.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  Deterministic work counters, incremented on the REAL path of the
 *  generation-6 freeze (g_nodus_storage_work in nodus_witness_v2_storage.c:
 *  registry rows read, segments visited, assignment rows read / written,
 *  scores computed) are read around two ORDINARY boundaries with the same
 *  membership and one new segment each:
 *   1. a boundary on a small history -> counters W1;
 *   2. an EVENT boundary (an arrival, operator exception D11): every
 *      published segment is visited once - segments_visited == the number
 *      of segments, counted SEPARATELY and not compared with the ordinary
 *      ones (plan T-9: "event boundaries counted separately");
 *   3. the history is grown (100 000 ended v2_storage_assign rows, 5 000
 *      published segments, 10 000 RELEASED registry rows - the registry row
 *      carries a 2 592-byte key, so 10^4 is 26 MB where 10^5 would be
 *      260 MB; the other two are the plan's 10^5 / the segment list at
 *      several thousand), then a second ordinary boundary -> counters W2;
 *   4. W2 == W1 in EVERY counter, and every counter of W1 that the path
 *      must touch is non-zero (the plan's false-pass guard: counters not
 *      wired to the real path).
 *  The mutation "visit every segment on an ordinary boundary" makes
 *  segments_visited of W2 grow with the history and fails step 4.
 *
 * ── WHAT IT DOES NOT COVER ──────────────────────────────────────────────
 *  The ordinary-block half (trie nodes loaded by the 8-pre flush of ONE
 *  changed key, counted in nodus_witness_v2_trie.c ts_get) is measured on
 *  a tokens leg of 100 and of 5 000 rows by trie_probe(): the path-depth
 *  BOUND (<= 131 nodes, plan 5.6) holds at both sizes and is far below the
 *  leg's size - not equality, because the depth grows with log16(rows).
 *  The flush is driven directly, not through a block; the other seven legs
 *  are empty. The settlement of a boundary, release and the registry point
 *  reads at settlement are not run here (no snapshots / reports): the
 *  counters cover the freeze and the flush only. registry_vm_steps is
 *  SQLite's own virtual-machine step count of the registry status query
 *  (compared within a 64-step BOUND: the indexed query drifted by 1 step,
 *  288 -> 289, when 10 000 RELEASED rows followed the ACTIVE range, while a
 *  scan adds 10 000+; see the check)
 *  (a positive control in main() shows a real scan - WHERE +status = 1,
 *  which disables the index - steps >= 10 000 more than the indexed query
 *  on the grown registry; NOT INDEXED is not honoured on this WITHOUT ROWID
 *  table).
 *
 * ── FLAGS ───────────────────────────────────────────────────────────────
 *  register_witness_test; EVM runtime only. No fault injection, no
 *  environment. Leaves /tmp/test_hf9_growth_XXXXXX (removed at exit).
 *
 * ── HOW IT CAN FALSELY PASS OR SKIP ─────────────────────────────────────
 *  Equal counters on a path that does no work are caught by the non-zero
 *  asserts. The planted history is deliberately NOT loader-well-formed
 *  (the RELEASED registry rows' fingerprints are not SHA3-512 of their
 *  key; the ended assignment rows and old segments have no matching
 *  relation): an ordinary generation-6 boundary never reads it, which IS
 *  the growth claim - a path that did read it would FAULT or move a
 *  counter, not pass silently. A counter that missed a read of the planted
 *  tables would pass: the counters sit on the freeze's queries against the
 *  assignment, segment and registry tables (the increments in
 *  nodus_witness_v2_storage.c), and the rows are deterministic functions
 *  of a counter (no randomblob).
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_storage.h"
#include "witness/nodus_witness_v2_trie.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/dnac.h"
#include "dnac/ledger_roots_v2.h"
#include "crypto/hash/qgp_sha3.h"

#include <dirent.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
    g_checks++; \
} while (0)

static int g_checks = 0;

#define E_LEN  ((uint64_t)DNAC_EPOCH_LENGTH)
#define NMEM   12u

static nodus_witness_t *g_w;
static char g_dir[128];
static uint8_t g_pk[NMEM][DNAC_PUBKEY_SIZE];
static uint8_t g_fp[NMEM][64];
static unsigned g_nseg;

static void rmrf(const char *path) {
    DIR *d = opendir(path);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            char c[512];
            snprintf(c, sizeof(c), "%s/%s", path, e->d_name);
            struct stat st;
            if (lstat(c, &st) == 0) {
                if (S_ISDIR(st.st_mode)) rmrf(c); else (void)unlink(c);
            }
        }
        closedir(d);
        (void)rmdir(path);
    } else {
        (void)unlink(path);
    }
}

static int sqlx(const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(g_w->db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL failed: %s [%s]\n", err ? err : "?", sql);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static int cc_row(unsigned param, uint64_t value, uint64_t effective,
                  uint64_t nonce) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_w->db,
            "INSERT INTO chain_config_history (param_id, new_value, "
            "effective_block, commit_block, tx_hash, proposal_nonce, "
            "created_at_unix) VALUES (?1, ?2, ?3, 0, zeroblob(64), ?4, 0)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)param);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)value);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)effective);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)nonce);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    g_w->chain_config_cache_warm = false;
    return rc == SQLITE_DONE ? 0 : -1;
}

static int reg_put(unsigned i) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_w->db,
            "INSERT INTO v2_storage_nodes (node_fp, node_pk, payee_fp, "
            "bond, status, registered_height, exit_height, fail_streak, "
            "grace_until) VALUES (?1, ?2, zeroblob(64), 1000, 1, 1, 0, 0, "
            "0)", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, g_fp[i], 64, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, g_pk[i], DNAC_PUBKEY_SIZE, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int seg_put(unsigned k, uint64_t pub) {
    uint8_t r[64];
    uint8_t pre[8] = { 'g', 'r', 'o', 'w', 0, 0, 0, 0 };
    pre[4] = (uint8_t)(k >> 8);
    pre[5] = (uint8_t)k;
    qgp_sha3_512(pre, sizeof(pre), r);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_w->db, "INSERT INTO v2_storage_segments (k, "
                           "root, published_height) VALUES (?1, ?2, ?3)",
                           -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(st, 1, (int)k);
    sqlite3_bind_blob(st, 2, r, 64, SQLITE_STATIC);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)pub);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    g_nseg = k;
    return rc == SQLITE_DONE ? 0 : -1;
}

static int plant_set(uint64_t H, unsigned count) {
    uint8_t fps[NMEM][64];
    for (unsigned i = 0; i < count; i++) memcpy(fps[i], g_fp[i], 64);
    for (unsigned i = 1; i < count; i++)
        for (unsigned j = i; j > 0 && memcmp(fps[j - 1], fps[j], 64) > 0; j--) {
            uint8_t t[64];
            memcpy(t, fps[j], 64);
            memcpy(fps[j], fps[j - 1], 64);
            memcpy(fps[j - 1], t, 64);
        }
    uint8_t sh[64];
    if (dna_v2_storage_set_hash(H, (const uint8_t (*)[64])fps, count, sh))
        return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_w->db, "INSERT INTO v2_storage_sets "
            "(epoch_start, set_hash, member_count) VALUES (?1, ?2, ?3)", -1,
            &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)H);
    sqlite3_bind_blob(st, 2, sh, 64, SQLITE_STATIC);
    sqlite3_bind_int(st, 3, (int)count);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;
    for (unsigned i = 0; i < count; i++) {
        st = NULL;
        if (sqlite3_prepare_v2(g_w->db, "INSERT INTO v2_storage_set_members "
                "(epoch_start, node_fp, fail_streak, grace_until) VALUES "
                "(?1, ?2, 0, 0)", -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)H);
        sqlite3_bind_blob(st, 2, fps[i], 64, SQLITE_STATIC);
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) return -1;
    }
    return 0;
}

/* one generation-6 boundary; the counters of that freeze alone in *wk */
static int freeze(uint64_t B, unsigned n_new_seg, nodus_storage_work_t *wk) {
    for (unsigned i = 0; i < n_new_seg; i++)
        if (seg_put(g_nseg + 1, B) != 0) return -1;
    nodus_storage_boundary_t out;
    memset(&out, 0, sizeof(out));
    out.n_published = n_new_seg;
    if (sqlx("BEGIN IMMEDIATE") != 0) return -1;
    memset(&g_nodus_storage_work, 0, sizeof(g_nodus_storage_work));
    int rc = nodus_witness_storage_freeze_gen6(
                 g_w, B, 4, DNA_V2_STORAGE_SET_LIMIT_GEN6, &out);
    *wk = g_nodus_storage_work;
    if (rc != 0) { (void)sqlx("ROLLBACK"); return -1; }
    return sqlx("COMMIT");
}

/* The flush of ONE changed key on a tokens leg of `n_tokens` rows: a fresh
 * S20 chain, the tokens planted, the eight tries built (the edge's step),
 * capture on, one more token written (the trigger captures it), then the
 * phase-8-pre flush with the counters read around it. The planted tokens
 * only fill leg 2; the other seven legs are empty. */
static int trie_probe(unsigned n_tokens, uint64_t *loaded) {
    char sql[800];
    g_w = calloc(1, sizeof(*g_w));
    CHECK(g_w != NULL, "alloc");
    snprintf(g_dir, sizeof(g_dir), "/tmp/test_hf9_growth_XXXXXX");
    CHECK(mkdtemp(g_dir) != NULL, "tmpdir");
    snprintf(g_w->data_path, sizeof(g_w->data_path), "%s", g_dir);
    uint8_t c16[16];
    memset(c16, 0x47, sizeof(c16));
    CHECK(nodus_witness_create_chain_db(g_w, c16) == 0 &&
          nodus_witness_db_migrate_v2s20(g_w) == 0, "fixture");
    static const char *const ins =
        "WITH RECURSIVE c(i) AS (SELECT %u UNION ALL SELECT i + 1 FROM c "
        "WHERE i < %u) INSERT INTO tokens (token_id, name, symbol, "
        "decimals, supply, creator_fp, flags, block_height, timestamp) "
        "SELECT CAST(zeroblob(64 - length(CAST(i AS TEXT))) || "
        "CAST(i AS BLOB) AS BLOB), 'tok' || i, 'T' || i, 8, 1000, 'fp1', "
        "1, 7, 99 FROM c";
    snprintf(sql, sizeof(sql), ins, 1u, n_tokens);
    CHECK(sqlx(sql) == 0, "tokens planted");
    CHECK(sqlx("BEGIN IMMEDIATE") == 0, "begin");
    CHECK(nodus_witness_v2_trie_build_all(g_w) == 0 &&
          nodus_witness_v2_trie_dirty_clear(g_w) == 0 &&
          nodus_witness_v2_trie_set_capture(g_w, 1) == 0,
          "the tries built, capture on");
    CHECK(sqlx("COMMIT") == 0, "commit");
    snprintf(sql, sizeof(sql), ins, n_tokens + 1u, n_tokens + 1u);
    CHECK(sqlx("BEGIN IMMEDIATE") == 0 && sqlx(sql) == 0,
          "one more token (captured)");
    int64_t dirty = 0;
    CHECK(nodus_witness_v2_trie_dirty_count(g_w, &dirty) == 0 && dirty == 1,
          "exactly one dirty key");
    memset(&g_nodus_storage_work, 0, sizeof(g_nodus_storage_work));
    CHECK(nodus_witness_v2_trie_flush(g_w) == 0, "the flush");
    *loaded = g_nodus_storage_work.trie_nodes_loaded;
    CHECK(sqlx("COMMIT") == 0, "commit");
    sqlite3_close(g_w->db);
    free(g_w);
    rmrf(g_dir);
    return 0;
}

int main(void) {
    for (unsigned i = 0; i < NMEM; i++) {
        for (size_t j = 0; j < DNAC_PUBKEY_SIZE; j++)
            g_pk[i][j] = (uint8_t)(i * 29u + j * 13u + 3u);
        g_pk[i][0] = (uint8_t)i;
        g_pk[i][1] = 0xB2;
        if (qgp_sha3_512(g_pk[i], DNAC_PUBKEY_SIZE, g_fp[i]) != 0) return 1;
    }
    g_w = calloc(1, sizeof(*g_w));
    CHECK(g_w != NULL, "alloc");
    snprintf(g_dir, sizeof(g_dir), "/tmp/test_hf9_growth_XXXXXX");
    CHECK(mkdtemp(g_dir) != NULL, "tmpdir");
    snprintf(g_w->data_path, sizeof(g_w->data_path), "%s", g_dir);
    uint8_t c16[16];
    memset(c16, 0x46, sizeof(c16));
    CHECK(nodus_witness_create_chain_db(g_w, c16) == 0 &&
          nodus_witness_db_migrate_v2s20(g_w) == 0, "fixture");

    /* history: set(H2) of 10 members, segments 1..4 published at H2 */
    CHECK(plant_set(5 * E_LEN, 10) == 0, "set(H2)");
    for (unsigned i = 0; i < 10; i++) CHECK(reg_put(i) == 0, "registry");
    for (unsigned k = 1; k <= 4; k++) CHECK(seg_put(k, 5 * E_LEN) == 0, "seg");
    CHECK(cc_row(DNAC_CFG_RULESET_GEN_ROLES, 1, 1, 1) == 0 &&
          cc_row(DNAC_CFG_RULESET_GEN_TRIE, 1, 5 * E_LEN + 2, 2) == 0,
          "params");
    CHECK(sqlx("BEGIN IMMEDIATE") == 0 &&
          nodus_witness_storage_gen6_transition(g_w, 5 * E_LEN + 1) == 0 &&
          sqlx("COMMIT") == 0, "edge");

    nodus_storage_work_t wk, w1, wev, w2;
    uint64_t B = 6 * E_LEN;
    CHECK(freeze(B, 1, &wk) == 0, "B1");

    /* 1. an event boundary (an arrival), counted SEPARATELY */
    CHECK(reg_put(10) == 0, "an arrival");
    B += E_LEN;
    CHECK(freeze(B, 0, &wev) == 0, "event boundary");
    CHECK(wev.segments_visited == g_nseg,
          "an event boundary visits every published segment once (D11)");
    CHECK(wev.assign_rows_read > 0 && wev.assign_rows_written > 0,
          "the assignment-row counters are wired to the real path (they "
          "are 0 on an ordinary boundary, so the event boundary proves "
          "them non-zero)");

    /* 2. an ordinary boundary on a small history (11 members, one new
     * segment) */
    B += E_LEN;
    CHECK(freeze(B, 1, &w1) == 0, "ordinary boundary 1");
    CHECK(w1.registry_rows_read >= 11 && w1.segments_visited == 1 &&
          w1.assign_rows_written == 4 && w1.scores_computed >= 11,
          "W1 is non-zero on every counter the path must touch (registry "
          "rows >= members, exactly the 1 new segment visited, R = 4 rows "
          "written, the eligible members scored)");

    /* 3. grow the history, then a second ordinary boundary */
    CHECK(sqlx("BEGIN") == 0, "begin");
    CHECK(sqlx("WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i + 1 "
               "FROM c WHERE i < 100000) INSERT INTO v2_storage_assign "
               "(k, node_fp, score, from_h, to_h) SELECT 1000000 + i, "
               "zeroblob(64), zeroblob(64), 1, 2 FROM c") == 0,
          "100 000 ended assignment rows");
    /* deterministic 64-byte blobs derived from the counter (no randomblob:
     * a test's data is a function of its source) */
    CHECK(sqlx("WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i + 1 "
               "FROM c WHERE i < 5000) INSERT INTO v2_storage_segments "
               "(k, root, published_height) SELECT 100 + i, "
               "CAST(zeroblob(64 - length(CAST(i AS TEXT))) || "
               "CAST(i AS BLOB) AS BLOB), 1 FROM c") == 0,
          "5 000 old segments");
    CHECK(sqlx("WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i + 1 "
               "FROM c WHERE i < 10000) INSERT INTO v2_storage_nodes "
               "(node_fp, node_pk, payee_fp, bond, status, "
               "registered_height, exit_height, fail_streak, grace_until) "
               "SELECT CAST(zeroblob(64 - length(CAST(i AS TEXT))) || "
               "CAST(i AS BLOB) AS BLOB), zeroblob(2592), zeroblob(64), 0, "
               "3, 1, 1, 0, 0 FROM c") == 0, "10 000 RELEASED registry rows");
    CHECK(sqlx("COMMIT") == 0, "commit");
    g_nseg = 5100;                    /* the planted k = 101 .. 5100 */
    B += E_LEN;
    CHECK(freeze(B, 1, &w2) == 0, "ordinary boundary 2 on the grown history");

    /* 4. equal in every counter */
    CHECK(w2.registry_rows_read == w1.registry_rows_read &&
          w2.segments_visited == w1.segments_visited &&
          w2.assign_rows_read == w1.assign_rows_read &&
          w2.assign_rows_written == w1.assign_rows_written &&
          w2.scores_computed == w1.scores_computed,
          "the work of an ordinary boundary does not depend on the "
          "history: every counter equal after the history grew by 10^5 "
          "assignment rows, 5 000 segments and 10^4 registry rows");
    CHECK(w2.segments_visited == 1 && w2.assign_rows_read == 0,
          "and it is the one new segment, no old assignment row read");
    /* work EXAMINED, not rows returned (Sol row 12, round 3 row 5):
     * SQLite's virtual-machine step count of the registry status query
     * (registry_vm_steps). Non-zero (wired), and EQUAL before and after
     * 10 000 RELEASED rows were added: the status index serves it. */
    CHECK(w1.registry_vm_steps > 0 && w2.registry_vm_steps > 0,
          "the registry work counter is wired (non-zero)");
    /* A BOUND, not equality: main measured the indexed status query at 288
     * VM steps before and 289 after 10 000 RELEASED rows (EXPLAIN QUERY
     * PLAN: SEARCH ... USING INDEX v2_storage_nodes_by_status (status=?)
     * both times) - the index range ends one entry later when rows follow
     * the ACTIVE range. A scan steps once per registry row, i.e. at least
     * 10 000 more; the bound of 64 is far above the index's one-step
     * drift and far below a scan. */
    CHECK(w2.registry_vm_steps <= w1.registry_vm_steps + 64 &&
          w1.registry_vm_steps <= w2.registry_vm_steps + 64,
          "the registry status query examines the same work (within 64 VM "
          "steps) before and after the history grew - a scan would add "
          "one step per RELEASED row (10 000+)");
    /* positive control: the measure DOES see scan work. The same query
     * with the index disabled steps at least once per RELEASED row more
     * than the indexed one. */
    {
        long long steps[2] = { -1, -1 };
        static const char *const q[2] = {
            "SELECT node_fp FROM v2_storage_nodes WHERE status = 1",
            /* NOT INDEXED is not honoured on this WITHOUT ROWID table
             * (SQLite 3.40.1: still "SEARCH ... USING COVERING INDEX"),
             * so the unary plus on the column disables the index instead:
             * "SCAN v2_storage_nodes" (main measured 30 144 steps on
             * 16 + 10 000 rows) */
            "SELECT node_fp FROM v2_storage_nodes WHERE +status = 1 "
            "ORDER BY node_fp ASC" };
        for (int i = 0; i < 2; i++) {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(g_w->db, q[i], -1, &st, NULL)
                  == SQLITE_OK, "control query");
            while (sqlite3_step(st) == SQLITE_ROW) { }
            steps[i] = sqlite3_stmt_status(st, SQLITE_STMTSTATUS_VM_STEP, 0);
            sqlite3_finalize(st);
        }
        CHECK(steps[0] > 0 && steps[1] >= steps[0] + 10000,
              "control: the real scan (+status) steps at least 10 000 more "
              "than the indexed query - the counter can see the difference");
    }

    sqlite3_close(g_w->db);
    free(g_w);
    rmrf(g_dir);

    /* 5. the ordinary-block half of T-9: trie nodes loaded by the flush of
     * ONE changed key, on a tokens leg of 100 and of 5 000 rows */
    {
        uint64_t l_small = 0, l_big = 0;
        CHECK(trie_probe(100, &l_small) == 0, "trie probe, 100 tokens");
        CHECK(trie_probe(5000, &l_big) == 0, "trie probe, 5 000 tokens");
        /* plan 5.6: one changed key loads at most its path (<= 129 nodes)
         * + 1 sibling + 1 extension child. The path depth grows only with
         * log16(rows), so the bound - not equality - is the invariant. */
        CHECK(l_small > 0 && l_big > 0,
              "the trie-node counter is wired (non-zero)");
        CHECK(l_small <= 131 && l_big <= 131,
              "one changed key loads at most 131 nodes at either size");
        CHECK(l_big < 5000 / 4,
              "and nowhere near the leg's size: no full reload");
    }
    printf("test_hf9_growth: ALL %d checks passed\n", g_checks);
    return 0;
}
