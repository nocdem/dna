/**
 * Nodus — HF-9 H2: schema S20 (the node-local tree tables and the four
 * storage-table rebuilds). Real witness chain DBs in temp dirs (heap
 * fixture). Spec: docs/plans/2026-10-23-hf9-byte-spec.md rev 3 §8, §9,
 * §12a.6(c), §13 "Schema S20 and replay".
 *
 * WHAT IT PROVES (each would be false if its group failed):
 *   1. a fresh database climbs to user_version 20 and carries v2_tree_ctx,
 *      v2_tree_nodes (exactly digest + rlp), v2_tree_roots,
 *      v2_tree_compwit (and no v2_tree_gc table), the 19
 *      v2_tree_dirty_<trie> tables and the 21 v2_tree_shadow_<table>
 *      tables (each shadow = height, op + EVERY column of its live source
 *      table, in order); the storage tables carry exactly the S20 text of
 *      nodus_witness.h; a second run is a no-op;
 *   2. a database in the S19 shape with rows in all four rebuilt tables
 *      migrates to S20 keeping EVERY row and every old column value, the
 *      new columns take their DEFAULTs (copies 3, placeable 0, empty
 *      ipv4s, ipv4 0, ipv4_since 0), the registry's payee index is back,
 *      and the new CHECKs bite (member_count <= 1024, copies 3..16,
 *      bitmap <= 128, ipv4s a multiple of 4 and <= 4096, placeable 0/1,
 *      ipv4 a u32);
 *   3. a failure inside the rung (every injected stage, and a storage
 *      table in neither text) rolls back whole: version still 19, the S19
 *      text and every row intact, no tree table; a clean run afterwards
 *      succeeds;
 *   4. the open-time shape check accepts the S19 storage text only while
 *      user_version < 20 and refuses it at 20;
 *   5. an unknown newer version (21) fails closed, nothing changes;
 *   6. a database ALREADY at S20 is held to the S20 shape at every open:
 *      a dropped or loosened tree table, a dropped shadow / dirty table or
 *      a missing payee index is refused (verify_v2s20_shape and the open).
 *   Group 2 compares the COMPLETE old-column tuple of every row of the
 *   four tables (hex of every blob, distinct values per row) before and
 *   after; group 1 compares each shadow's complete primary-key sequence.
 *
 * WHAT IT REQUIRES: a default build (nothing from the environment, no
 * fault-injection flag, no epoch constant). Temp directories under /tmp.
 *
 * WHAT IT LEAVES BEHIND: nothing; every fixture removes its directory.
 *
 * HOW IT CAN LIE: the S19 shape is rebuilt BY HAND from the *_S19_DDL
 * macros of nodus_witness.h (group 2-4), so it proves the rung against
 * those texts, not against a database a previous binary wrote — a
 * mistake in the macros themselves (they are meant to be the previous
 * build's text byte for byte) is invisible here. Groups 1-3 use a bare
 * pre-genesis database and call the rung directly (it can never be
 * REOPENED: the role gate refuses the S14 stores without a stored genesis
 * document). Everything that reopens (groups 4 and 6, and the at-open
 * rung climbing a chain put back to S19) uses a REAL derived version-3
 * chain (v2_genesis_fixture.h TIER A); each refusal there is preceded by
 * the same chain reopening untampered.
 * No row is replayed from genesis here (that is the existing
 * version-3 fixtures' job, which reach S20 through the at-open rung).
 *
 * @file test_hf9_schema.c
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "nodus/nodus_chain_config.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "dnac/dnac.h"
#include "dnac/manifest_wire.h"
#include "dnac/vset_wire.h"
#include "dnac/block_v2.h"

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "v2_genesis_fixture.h"   /* TIER A: a REAL version-3 chain with a
                                   * stored genesis document (it reopens) */

/* Distinct fixture values as SQL expressions: BL(n) a 64-byte blob (n as
 * zero-padded digits), PK(n) a 2592-byte blob, BM(len, n) a len-byte
 * blob. (SQLite's || on two blobs yields TEXT, so printf + CAST.) */
#define BL(n)     "CAST(printf('%064d', " #n ") AS BLOB)"
#define PK(n)     "CAST(printf('%02592d', " #n ") AS BLOB)"
#define BM(len, n) "CAST(printf('%0" #len "d', " #n ") AS BLOB)"

/* the old-column dump make_s19_db took (one fixture alive at a time) */
static char g_old_dump[64 * 1024];
static int dump_old(sqlite3 *db, char *out, size_t cap);

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

static void rmrf(const char *path) {
    DIR *d = opendir(path);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 ||
                strcmp(ent->d_name, "..") == 0) continue;
            char child[1024];
            snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
            struct stat st;
            if (lstat(child, &st) == 0) {
                if (S_ISDIR(st.st_mode)) rmrf(child);
                else (void)unlink(child);
            }
        }
        closedir(d);
        (void)rmdir(path);
    } else {
        (void)unlink(path);
    }
}

typedef struct {
    nodus_witness_t *w;
    char             dir[256];
    uint8_t          chain_id16[16];
} fixture_t;

static int fx_open(fixture_t *fx) {
    fx->w = calloc(1, sizeof(*fx->w));   /* multi-MB — ALWAYS heap */
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_hf9_schema_XXXXXX");
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain_id16, 0x39, sizeof(fx->chain_id16));
    if (nodus_witness_create_chain_db(fx->w, fx->chain_id16) != 0) {
        rmrf(fx->dir); free(fx->w); fx->w = NULL;
        return -1;
    }
    return 0;
}

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) { sqlite3_close(fx->w->db); fx->w->db = NULL; }
    free(fx->w);
    fx->w = NULL;
    rmrf(fx->dir);
}

static int run_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL failed: %s\n", err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

/* 1 = the statement is refused by SQLite (a CHECK biting), 0 = it ran. */
static int sql_refused(sqlite3 *db, const char *sql) {
    return sqlite3_exec(db, sql, NULL, NULL, NULL) != SQLITE_OK;
}

#define Q_FAULT INT64_MIN

/* first column of the first row as int64; Q_FAULT on any fault / no row */
static int64_t q1(sqlite3 *db, const char *sql) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return Q_FAULT;
    int64_t v = Q_FAULT;
    if (sqlite3_step(st) == SQLITE_ROW) v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

/* a fault stays a fault (-1): an absence check (== 0) must never pass
 * after a failed query */
static int q1_int(sqlite3 *db, const char *sql) {
    int64_t v = q1(db, sql);
    return v == Q_FAULT ? -1 : (int)v;
}

static int has_table(sqlite3 *db, const char *name) {
    char sql[256];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM sqlite_master WHERE "
             "type='table' AND name='%s'", name);
    return q1_int(db, sql);
}

static int has_col(sqlite3 *db, const char *table, const char *col) {
    char sql[256];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM pragma_table_info('%s') "
             "WHERE name='%s'", table, col);
    return q1_int(db, sql);
}

/* 1 = `table`'s stored sqlite_master.sql equals what this build's SQLite
 * stores for `ddl`, 0 = differs / absent, -1 = fault. The reference is
 * produced in a private :memory: database — the check the production code
 * makes (nodus_witness.c witness_ddl_shape_cmp), re-implemented here so a
 * mistake there cannot hide behind itself. */
static int ddl_is(sqlite3 *db, const char *table, const char *ddl) {
    static const char *const q =
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1";
    sqlite3 *mem = NULL;
    sqlite3_stmt *a = NULL, *b = NULL;
    int out = -1;
    if (sqlite3_open(":memory:", &mem) != SQLITE_OK) {
        if (mem) sqlite3_close(mem);
        return -1;
    }
    if (sqlite3_exec(mem, ddl, NULL, NULL, NULL) == SQLITE_OK &&
        sqlite3_prepare_v2(mem, q, -1, &a, NULL) == SQLITE_OK &&
        sqlite3_bind_text(a, 1, table, -1, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_prepare_v2(db, q, -1, &b, NULL) == SQLITE_OK &&
        sqlite3_bind_text(b, 1, table, -1, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_step(a) == SQLITE_ROW) {
        int rb = sqlite3_step(b);
        if (rb == SQLITE_DONE) {
            out = 0;
        } else if (rb == SQLITE_ROW) {
            const unsigned char *sa = sqlite3_column_text(a, 0);
            const unsigned char *sb = sqlite3_column_text(b, 0);
            int la = sqlite3_column_bytes(a, 0);
            int lb = sqlite3_column_bytes(b, 0);
            out = (sa && sb && la == lb && memcmp(sa, sb, (size_t)la) == 0)
                      ? 1 : 0;
        }
    }
    sqlite3_finalize(a);
    sqlite3_finalize(b);
    sqlite3_close(mem);
    return out;
}

static int all_s20_text(sqlite3 *db) {
    return ddl_is(db, "v2_storage_sets", NODUS_V2_STSETS_DDL) == 1 &&
           ddl_is(db, "v2_storage_set_members", NODUS_V2_STMEMB_DDL) == 1 &&
           ddl_is(db, "v2_storage_reports", NODUS_V2_STREPS_DDL) == 1 &&
           ddl_is(db, "v2_storage_nodes", NODUS_V2_STORAGE_DDL) == 1 &&
           ddl_is(db, "v2_storage_segments", NODUS_V2_STSEGS_DDL) == 1;
}

static int all_s19_text(sqlite3 *db) {
    return ddl_is(db, "v2_storage_sets", NODUS_V2_STSETS_S19_DDL) == 1 &&
           ddl_is(db, "v2_storage_set_members", NODUS_V2_STMEMB_S19_DDL) == 1 &&
           ddl_is(db, "v2_storage_reports", NODUS_V2_STREPS_S19_DDL) == 1 &&
           ddl_is(db, "v2_storage_nodes", NODUS_V2_STORAGE_S19_DDL) == 1;
}

/* the 19 dirty tables of spec §3 and the 21 shadow sources of spec §9 */
static const char *const DIRTY[] = {
    "utxo", "token", "pools", "claims", "names", "accrual", "validator",
    "delegation", "chain_config", "vset", "manifest", "attendance",
    "st_registry", "st_sets", "st_reports", "st_segments", "bcopy",
    "stmem", "replay"
};
static const char *const SHADOW_SRC[] = {
    "utxo_set", "tokens", "v2_pools", "v2_pool_roots", "v2_claims_spent",
    "v2_names", "v2_reward_accrual", "chain_config_history",
    "validator_set_snapshots", "v2_manifests", "v2_attendance_epoch",
    "v2_storage_reports", "v2_storage_segments", "v2_balance_copy",
    "v2_replay", "validators", "v2_validator_roles", "delegations",
    "v2_storage_sets", "v2_storage_set_members", "v2_storage_nodes"
};
#define N_DIRTY  (sizeof(DIRTY) / sizeof(DIRTY[0]))
#define N_SHADOW (sizeof(SHADOW_SRC) / sizeof(SHADOW_SRC[0]))

#define COLS_MAX 64

/* Read (name, pk) of every column of `table`, in cid order, to the END of
 * the scan (SQLITE_DONE required). Returns the column count, -1 = fault /
 * more than COLS_MAX columns / a scan that did not end in SQLITE_DONE. */
static int read_cols(sqlite3 *db, const char *table,
                     char names[][64], int pk[]) {
    char sql[256];
    snprintf(sql, sizeof(sql), "SELECT name, pk FROM pragma_table_info('%s') "
             "ORDER BY cid", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int n = 0, rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const char *nm = (const char *)sqlite3_column_text(st, 0);
        if (!nm || n >= COLS_MAX || strlen(nm) >= 64) {
            sqlite3_finalize(st);
            return -1;
        }
        snprintf(names[n], 64, "%s", nm);
        pk[n] = sqlite3_column_int(st, 1);
        n++;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? n : -1;
}

/* 1 = v2_tree_shadow_<src> is (height, op, <every column of src, in
 * order>) and its primary key is EXACTLY (height, <the source's key
 * columns in key order>) — the complete pk sequence, not only its first
 * member; both scans ran to SQLITE_DONE. 0 = not; -1 = fault. */
static int shadow_ok(sqlite3 *db, const char *src) {
    char sh[96];
    char sn[COLS_MAX][64], hn[COLS_MAX][64];
    int spk[COLS_MAX], hpk[COLS_MAX];
    snprintf(sh, sizeof(sh), "v2_tree_shadow_%s", src);
    int ns = read_cols(db, src, sn, spk);
    int nh = read_cols(db, sh, hn, hpk);
    if (ns < 0 || nh < 0) return -1;
    if (ns == 0 || nh != ns + 2) return 0;
    if (strcmp(hn[0], "height") != 0 || hpk[0] != 1 ||
        strcmp(hn[1], "op") != 0 || hpk[1] != 0)
        return 0;
    int n_key = 0;
    for (int i = 0; i < ns; i++) {
        if (strcmp(sn[i], hn[i + 2]) != 0) return 0;
        /* a source key column of position k is position k + 1 in the
         * shadow key (height is position 1); a non-key stays 0 */
        if (hpk[i + 2] != (spk[i] > 0 ? spk[i] + 1 : 0)) return 0;
        if (spk[i] > 0) n_key++;
    }
    return n_key > 0 ? 1 : 0;
}

/* The S19 shape, rebuilt BY HAND: a fresh fixture, the S19 rung, then the
 * four storage tables replaced by their S19 text and filled with rows
 * (explicit column lists, so the rows are valid under the S19 CHECKs). */
static int s19_shape(sqlite3 *db) {
    if (run_sql(db,
            "DROP TABLE v2_storage_sets;"
            "DROP TABLE v2_storage_set_members;"
            "DROP TABLE v2_storage_reports;"
            "DROP TABLE v2_storage_nodes;"
            NODUS_V2_STSETS_S19_DDL ";"
            NODUS_V2_STMEMB_S19_DDL ";"
            NODUS_V2_STREPS_S19_DDL ";"
            NODUS_V2_STORAGE_S19_DDL ";"
            "CREATE INDEX idx_v2_storage_nodes_payee ON "
            "v2_storage_nodes(payee_fp);"
            /* every key / blob value is DISTINCT (BL / PK build a
             * different 64 / 2592-byte value per number), so a copy that
             * crossed rows or columns shows in the tuple comparison */
            "INSERT INTO v2_storage_sets (epoch_start, set_hash, "
            "member_count) VALUES (15, " BL(115) ", 200), "
            "(30, " BL(130) ", 0), (45, " BL(145) ", 256);"
            "INSERT INTO v2_storage_set_members (epoch_start, node_fp, "
            "fail_streak, grace_until) VALUES "
            "(15, " BL(1) ", 1, 20), (15, " BL(2) ", 2, 0), "
            "(45, " BL(3) ", 3, 77);"
            "INSERT INTO v2_storage_reports (epoch_start, seat, set_hash, "
            "bitmap) VALUES (15, 0, " BL(215) ", " BM(32, 7) "), "
            "(15, 1, " BL(216) ", x''), (45, 9, " BL(245) ", " BM(5, 8) ");"
            "INSERT INTO v2_storage_nodes (node_fp, node_pk, payee_fp, "
            "bond, status, registered_height, exit_height, fail_streak, "
            "grace_until) VALUES "
            "(" BL(11) ", " PK(21) ", " BL(911) ", 777, 1, 3, 0, 0, 0), "
            "(" BL(12) ", " PK(22) ", " BL(912) ", 5, 2, 4, 9, 2, 11), "
            "(" BL(13) ", " PK(23) ", " BL(913) ", 6, 3, 8, 12, 4, 13)") != 0)
        return -1;
    return dump_old(db, g_old_dump, sizeof(g_old_dump));
}

/* bare pre-genesis fixture at S19 in the S19 shape (direct-rung tests
 * only: it has no stored genesis document and so cannot be REOPENED —
 * the role gate refuses a database with the S14 stores and no document) */
static int make_s19_db(fixture_t *fx) {
    if (fx_open(fx) != 0) return -1;
    if (nodus_witness_db_migrate_v2s19(fx->w) != 0) return -1;
    return s19_shape(fx->w->db);
}

/* a REAL version-3 chain (derivation + production open: stored genesis
 * document, so it reopens) and its reopen. After v2x_chain_open the
 * chain is at S20 — the derivation stops at S19 and the production open
 * climbs it. */
static int chain_reopen(v2x_chain_t *c) {
    if (c->w->db) sqlite3_close(c->w->db);
    c->w->db = NULL;
    return nodus_witness_create_chain_db(c->w, c->chain32);
}

static int chain_open_s20(v2x_chain_t *c, const char *tag) {
    uint32_t ver = 0;
    if (v2x_chain_open(c, tag, 1) != 0) return -1;
    if (nodus_witness_db_schema_version(c->w, &ver) != 0 ||
        ver != NODUS_V2_SCHEMA_VERSION_S20) {
        v2x_chain_close(c);
        return -1;
    }
    return 0;
}

/* Every old column of every row of the four tables, ordered by primary
 * key, as text (hex for blobs), appended to out. */
static int dump_old(sqlite3 *db, char *out, size_t cap) {
    static const char *const q[] = {
        "SELECT epoch_start || ':' || hex(set_hash) || ':' || member_count "
        "FROM v2_storage_sets ORDER BY epoch_start",
        "SELECT epoch_start || ':' || hex(node_fp) || ':' || fail_streak "
        "|| ':' || grace_until FROM v2_storage_set_members "
        "ORDER BY epoch_start, node_fp",
        "SELECT epoch_start || ':' || seat || ':' || hex(set_hash) || ':' "
        "|| hex(bitmap) FROM v2_storage_reports ORDER BY epoch_start, seat",
        "SELECT hex(node_fp) || ':' || hex(node_pk) || ':' || hex(payee_fp) "
        "|| ':' || bond || ':' || status || ':' || registered_height || ':' "
        "|| exit_height || ':' || fail_streak || ':' || grace_until "
        "FROM v2_storage_nodes ORDER BY node_fp"
    };
    size_t len = 0;
    out[0] = '\0';
    for (size_t i = 0; i < sizeof(q) / sizeof(q[0]); i++) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(db, q[i], -1, &st, NULL) != SQLITE_OK)
            return -1;
        int rc;
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            const char *t = (const char *)sqlite3_column_text(st, 0);
            size_t n = t ? strlen(t) : 0;
            if (!t || len + n + 2 >= cap) { sqlite3_finalize(st); return -1; }
            memcpy(out + len, t, n);
            out[len + n] = '\n';
            out[len + n + 1] = '\0';
            len += n + 1;
        }
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) return -1;
        if (len + 2 >= cap) return -1;
        out[len++] = '#';                 /* table separator */
        out[len] = '\0';
    }
    return 0;
}

/* 1 = the complete old-column tuple of EVERY row, by primary key, equals
 * what make_s19_db wrote (g_old_dump taken right after the inserts). */
static int s19_rows_intact(sqlite3 *db) {
    static char now[sizeof(g_old_dump)];
    if (dump_old(db, now, sizeof(now)) != 0) return 0;
    return g_old_dump[0] != '\0' && strcmp(now, g_old_dump) == 0;
}

static int test_fresh(void) {
    fixture_t fx;
    uint32_t ver = 0;
    CHECK(fx_open(&fx) == 0, "fresh fixture"); OK();
    CHECK(has_table(fx.w->db, "v2_tree_ctx") == 0,
          "no tree table before the rung"); OK();
    CHECK(nodus_witness_db_migrate_v2s20(fx.w) == 0, "0 -> 20"); OK();
    CHECK(nodus_witness_db_schema_version(fx.w, &ver) == 0 &&
          ver == NODUS_V2_SCHEMA_VERSION_S20 && ver == 20u,
          "user_version 20"); OK();

    CHECK(has_table(fx.w->db, "v2_tree_ctx") == 1 &&
          has_table(fx.w->db, "v2_tree_nodes") == 1 &&
          has_table(fx.w->db, "v2_tree_roots") == 1 &&
          has_table(fx.w->db, "v2_tree_compwit") == 1,
          "the four fixed tree tables"); OK();
    CHECK(has_table(fx.w->db, "v2_tree_gc") == 0,
          "no v2_tree_gc table (HF-9 keeps every committed node)"); OK();
    CHECK(has_col(fx.w->db, "v2_tree_ctx", "height") == 1 &&
          has_col(fx.w->db, "v2_tree_nodes", "digest") == 1 &&
          has_col(fx.w->db, "v2_tree_nodes", "rlp") == 1 &&
          has_col(fx.w->db, "v2_tree_roots", "domain") == 1 &&
          has_col(fx.w->db, "v2_tree_roots", "root") == 1 &&
          has_col(fx.w->db, "v2_tree_compwit", "slot") == 1 &&
          has_col(fx.w->db, "v2_tree_compwit", "data") == 1,
          "the fixed tables' columns"); OK();
    CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM pragma_table_info("
                       "'v2_tree_nodes')") == 2 &&
          has_col(fx.w->db, "v2_tree_nodes", "refs") == 0,
          "v2_tree_nodes has exactly digest and rlp (no refs column)"); OK();

    for (size_t i = 0; i < N_DIRTY; i++) {
        char t[96];
        snprintf(t, sizeof(t), "v2_tree_dirty_%s", DIRTY[i]);
        CHECK(has_table(fx.w->db, t) == 1, "a dirty table is missing");
    }
    OK();
    CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM sqlite_master WHERE "
                       "type='table' AND name LIKE 'v2_tree_dirty\\_%' "
                       "ESCAPE '\\'") == (int64_t)N_DIRTY,
          "exactly one dirty table per trie"); OK();
    CHECK(has_col(fx.w->db, "v2_tree_dirty_pools", "domain_id") == 1 &&
          has_col(fx.w->db, "v2_tree_dirty_pools", "pool_id") == 1 &&
          has_col(fx.w->db, "v2_tree_dirty_claims", "target_domain_id") == 1 &&
          has_col(fx.w->db, "v2_tree_dirty_claims", "nullifier") == 1 &&
          has_col(fx.w->db, "v2_tree_dirty_bcopy", "kind") == 1 &&
          has_col(fx.w->db, "v2_tree_dirty_st_reports", "seat") == 1,
          "dirty key columns (domain for pools / claims)"); OK();

    for (size_t i = 0; i < N_SHADOW; i++)
        CHECK(shadow_ok(fx.w->db, SHADOW_SRC[i]) == 1,
              "a shadow table is not (height, op, every source column)");
    OK();
    CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM sqlite_master WHERE "
                       "type='table' AND name LIKE 'v2_tree_shadow\\_%' "
                       "ESCAPE '\\'") == (int64_t)N_SHADOW,
          "exactly one shadow table per source"); OK();
    CHECK(has_col(fx.w->db, "v2_tree_shadow_utxo_set", "domain_id") == 1,
          "the shadow of utxo_set carries its S5 domain_id"); OK();
    CHECK(has_col(fx.w->db, "v2_tree_shadow_v2_storage_set_members",
                  "placeable") == 1 &&
          has_col(fx.w->db, "v2_tree_shadow_v2_storage_reports", "ipv4s") ==
              1 &&
          has_col(fx.w->db, "v2_tree_shadow_v2_storage_sets", "copies") == 1 &&
          has_col(fx.w->db, "v2_tree_shadow_v2_storage_nodes", "ipv4") == 1,
          "the shadows of the rebuilt tables carry the NEW columns"); OK();

    CHECK(all_s20_text(fx.w->db), "the storage tables are in the S20 text");
    OK();
    CHECK(has_col(fx.w->db, "v2_storage_sets", "copies") == 1 &&
          has_col(fx.w->db, "v2_storage_set_members", "placeable") == 1 &&
          has_col(fx.w->db, "v2_storage_reports", "ipv4s") == 1 &&
          has_col(fx.w->db, "v2_storage_nodes", "ipv4") == 1 &&
          has_col(fx.w->db, "v2_storage_nodes", "ipv4_since") == 1,
          "the new storage columns"); OK();
    CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM sqlite_master WHERE "
                       "type='index' AND name='idx_v2_storage_nodes_payee' "
                       "AND tbl_name='v2_storage_nodes'") == 1,
          "the registry's payee index"); OK();

    /* idempotent, and the node-local tables stay empty */
    CHECK(nodus_witness_db_migrate_v2s20(fx.w) == 0, "second run"); OK();
    CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM v2_tree_nodes") == 0 &&
          q1(fx.w->db, "SELECT COUNT(*) FROM v2_tree_ctx") == 0,
          "no tree row is written by the rung"); OK();
    /* no trigger anywhere: capture is the HF-9 edge's */
    CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM sqlite_master WHERE "
                       "type='trigger'") == 0, "no trigger before the edge");
    OK();

    /* (a bare pre-genesis fixture cannot be reopened — the role gate
     * refuses the S14 stores without a stored genesis document; the
     * reopen of a migrated database is shown on a real chain in
     * test_open_shape_check / test_s20_open_drift) */
    fx_close(&fx);
    return 0;
}

static int test_s19_to_s20(void) {
    fixture_t fx;
    uint32_t ver = 0;
    CHECK(make_s19_db(&fx) == 0, "the S19 database with rows"); OK();
    CHECK(nodus_witness_db_schema_version(fx.w, &ver) == 0 && ver == 19u,
          "the fixture is at S19"); OK();
    CHECK(all_s19_text(fx.w->db) && !all_s20_text(fx.w->db),
          "the four tables are in the S19 text"); OK();
    CHECK(s19_rows_intact(fx.w->db), "the S19 rows are what the test wrote");
    OK();

    CHECK(nodus_witness_db_migrate_v2s20(fx.w) == 0, "19 -> 20"); OK();
    CHECK(nodus_witness_db_schema_version(fx.w, &ver) == 0 && ver == 20u,
          "user_version 20"); OK();
    CHECK(all_s20_text(fx.w->db), "the four tables are in the S20 text");
    OK();
    CHECK(s19_rows_intact(fx.w->db),
          "every row and every old column value kept"); OK();

    /* the new columns took their DEFAULTs */
    CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM v2_storage_sets "
                       "WHERE copies = 3") == 3, "copies default 3"); OK();
    CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM v2_storage_set_members "
                       "WHERE placeable = 0") == 3, "placeable default 0");
    OK();
    CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM v2_storage_reports "
                       "WHERE typeof(ipv4s) = 'blob' AND length(ipv4s) = 0") ==
              3, "ipv4s default empty blob"); OK();
    CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM v2_storage_nodes "
                       "WHERE ipv4 = 0 AND ipv4_since = 0") == 3,
          "ipv4 / ipv4_since default 0"); OK();
    CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM sqlite_master WHERE "
                       "type='index' AND name='idx_v2_storage_nodes_payee' "
                       "AND tbl_name='v2_storage_nodes'") == 1,
          "the payee index is back on the rebuilt registry"); OK();
    CHECK(q1(fx.w->db, "SELECT COUNT(*) FROM sqlite_master WHERE "
                       "name LIKE '%s19old'") == 0,
          "no renamed leftover"); OK();

    /* the new CHECKs bite, at their edges */
    sqlite3 *db = fx.w->db;
    CHECK(!sql_refused(db, "INSERT INTO v2_storage_sets (epoch_start, "
                           "set_hash, member_count, copies) VALUES "
                           "(60, zeroblob(64), 1024, 16)"),
          "member_count 1024 and copies 16 are valid"); OK();
    CHECK(sql_refused(db, "INSERT INTO v2_storage_sets (epoch_start, "
                          "set_hash, member_count) VALUES "
                          "(61, zeroblob(64), 1025)"), "member_count 1025");
    OK();
    CHECK(sql_refused(db, "INSERT INTO v2_storage_sets (epoch_start, "
                          "set_hash, member_count, copies) VALUES "
                          "(62, zeroblob(64), 1, 2)"), "copies 2"); OK();
    CHECK(sql_refused(db, "INSERT INTO v2_storage_sets (epoch_start, "
                          "set_hash, member_count, copies) VALUES "
                          "(63, zeroblob(64), 1, 17)"), "copies 17"); OK();
    CHECK(!sql_refused(db, "INSERT INTO v2_storage_reports (epoch_start, "
                           "seat, set_hash, bitmap, ipv4s) VALUES "
                           "(60, 0, zeroblob(64), zeroblob(128), "
                           "zeroblob(4096))"),
          "bitmap 128 and ipv4s 4096 are valid"); OK();
    CHECK(sql_refused(db, "INSERT INTO v2_storage_reports (epoch_start, "
                          "seat, set_hash, bitmap) VALUES "
                          "(61, 0, zeroblob(64), zeroblob(129))"),
          "bitmap 129"); OK();
    CHECK(sql_refused(db, "INSERT INTO v2_storage_reports (epoch_start, "
                          "seat, set_hash, bitmap, ipv4s) VALUES "
                          "(62, 0, zeroblob(64), x'', zeroblob(3))"),
          "ipv4s not a multiple of 4"); OK();
    CHECK(sql_refused(db, "INSERT INTO v2_storage_reports (epoch_start, "
                          "seat, set_hash, bitmap, ipv4s) VALUES "
                          "(63, 0, zeroblob(64), x'', zeroblob(4100))"),
          "ipv4s over 4096"); OK();
    CHECK(!sql_refused(db, "INSERT INTO v2_storage_set_members (epoch_start, "
                           "node_fp, fail_streak, grace_until, placeable) "
                           "VALUES (30, zeroblob(64), 0, 0, 1)"),
          "placeable 1 is valid"); OK();
    CHECK(sql_refused(db, "INSERT INTO v2_storage_set_members (epoch_start, "
                          "node_fp, fail_streak, grace_until, placeable) "
                          "VALUES (30, " BL(99) ", 0, 0, 2)"),
          "placeable 2"); OK();
    CHECK(!sql_refused(db, "UPDATE v2_storage_nodes SET ipv4 = 4294967295, "
                           "ipv4_since = 7 WHERE bond = 777"),
          "ipv4 u32 max is valid"); OK();
    CHECK(sql_refused(db, "UPDATE v2_storage_nodes SET ipv4 = 4294967296 "
                          "WHERE bond = 777"), "ipv4 above u32"); OK();
    CHECK(sql_refused(db, "UPDATE v2_storage_nodes SET ipv4_since = -1 "
                          "WHERE bond = 777"), "negative ipv4_since"); OK();

    fx_close(&fx);
    return 0;
}

static int test_rollback_and_refusal(void) {
    static const nodus_v2s20_mig_fail_t stages[] = {
        V2S20MIG_FAIL_AFTER_BEGIN, V2S20MIG_FAIL_AFTER_REVALIDATE,
        V2S20MIG_FAIL_AFTER_TABLES, V2S20MIG_FAIL_AFTER_VERIFY,
        V2S20MIG_FAIL_BEFORE_COMMIT
    };
    uint32_t ver = 0;

    /* every injected stage rolls the rung back whole */
    for (size_t i = 0; i < sizeof(stages) / sizeof(stages[0]); i++) {
        fixture_t fx;
        CHECK(make_s19_db(&fx) == 0, "the S19 database with rows");
        CHECK(nodus_witness_db_migrate_v2s20_ex(fx.w, stages[i]) == -1,
              "an injected failure is a failure");
        CHECK(nodus_witness_db_schema_version(fx.w, &ver) == 0 && ver == 19u,
              "the version is still 19");
        CHECK(all_s19_text(fx.w->db), "the S19 text is back");
        CHECK(s19_rows_intact(fx.w->db), "every S19 row is back");
        CHECK(has_table(fx.w->db, "v2_tree_ctx") == 0 &&
              has_table(fx.w->db, "v2_tree_dirty_utxo") == 0 &&
              has_table(fx.w->db, "v2_tree_shadow_utxo_set") == 0,
              "no tree table survived the rollback");
        CHECK(sqlite3_get_autocommit(fx.w->db),
              "no transaction is left open");
        CHECK(nodus_witness_db_migrate_v2s20(fx.w) == 0,
              "a clean run after the failure");
        CHECK(all_s20_text(fx.w->db) && s19_rows_intact(fx.w->db),
              "...and it migrates every row");
        fx_close(&fx);
    }
    OK();

    /* a storage table in NEITHER text is refused (tampered shape) */
    {
        fixture_t fx;
        CHECK(make_s19_db(&fx) == 0, "the S19 database with rows");
        CHECK(run_sql(fx.w->db,
                "DROP TABLE v2_storage_sets;"
                "CREATE TABLE v2_storage_sets (epoch_start INTEGER PRIMARY "
                "KEY, set_hash BLOB, member_count INTEGER);"
                "INSERT INTO v2_storage_sets VALUES (15, zeroblob(64), 9)") ==
                  0, "tamper v2_storage_sets");
        CHECK(nodus_witness_db_migrate_v2s20(fx.w) == -1,
              "a tampered table is refused"); OK();
        CHECK(nodus_witness_db_schema_version(fx.w, &ver) == 0 && ver == 19u,
              "the version is still 19"); OK();
        CHECK(has_table(fx.w->db, "v2_tree_ctx") == 0,
              "nothing was created"); OK();
        CHECK(ddl_is(fx.w->db, "v2_storage_sets", NODUS_V2_STSETS_DDL) == 0 &&
              ddl_is(fx.w->db, "v2_storage_nodes",
                     NODUS_V2_STORAGE_S19_DDL) == 1,
              "the tampered table and the others are untouched"); OK();
        fx_close(&fx);
    }

    /* a CHECK-less look-alike of a tree table is refused, not read through */
    {
        fixture_t fx;
        CHECK(make_s19_db(&fx) == 0, "the S19 database with rows");
        CHECK(run_sql(fx.w->db, "CREATE TABLE v2_tree_nodes (digest BLOB "
                                "PRIMARY KEY, rlp BLOB)") == 0,
              "plant a look-alike");
        CHECK(nodus_witness_db_migrate_v2s20(fx.w) == -1,
              "the look-alike is refused"); OK();
        CHECK(nodus_witness_db_schema_version(fx.w, &ver) == 0 && ver == 19u &&
              all_s19_text(fx.w->db), "rolled back whole"); OK();
        fx_close(&fx);
    }

    /* unknown newer version (21) fails closed, nothing changes */
    {
        fixture_t fx;
        CHECK(fx_open(&fx) == 0, "fixture");
        CHECK(run_sql(fx.w->db, "PRAGMA user_version = 21") == 0, "set 21");
        CHECK(nodus_witness_db_migrate_v2s20(fx.w) == -1,
              "version 21 migrated"); OK();
        CHECK(nodus_witness_db_schema_version(fx.w, &ver) == 0 && ver == 21u,
              "version 21 mutated"); OK();
        CHECK(has_table(fx.w->db, "v2_tree_ctx") == 0,
              "version 21 got a table"); OK();
        fx_close(&fx);
    }
    return 0;
}

/* The open-time checks, on REAL version-3 chains (a stored genesis
 * document: a bare pre-genesis fixture is refused at every open by the
 * role gate whatever its shape, which would make a "refused" assertion
 * vacuous). Every refusal is preceded by the CONTROL: the same chain
 * reopens before the tampering. */
static int test_open_shape_check(void) {
    v2x_chain_t c;
    uint32_t ver = 0;

    /* (1) the real upgrade path: a chain put back to the S19 shape (rows,
     * S19 text, user_version 19) reopens — the open check accepts the S19
     * text below S20, the at-open rung climbs and rebuilds, no row lost */
    CHECK(chain_open_s20(&c, "hf9shape") == 0, "a real chain at S20"); OK();
    CHECK(chain_reopen(&c) == 0, "control: the S20 chain reopens"); OK();
    CHECK(s19_shape(c.w->db) == 0 &&
          run_sql(c.w->db, "PRAGMA user_version = 19") == 0, "back to S19");
    CHECK(nodus_witness_db_schema_version(c.w, &ver) == 0 && ver == 19u &&
          all_s19_text(c.w->db) && s19_rows_intact(c.w->db),
          "the S19 shape with rows"); OK();
    CHECK(chain_reopen(&c) == 0,
          "the S19 text opens at user_version 19 (and the rung climbs)");
    OK();
    CHECK(nodus_witness_db_schema_version(c.w, &ver) == 0 && ver == 20u &&
          all_s20_text(c.w->db) && s19_rows_intact(c.w->db) &&
          nodus_witness_db_verify_v2s20_shape(c.w) == 0,
          "...to S20, every old tuple kept"); OK();

    /* (2) from S20 on the S19 text is not a shape: ONE table put back */
    CHECK(chain_reopen(&c) == 0, "control: still reopens"); OK();
    CHECK(run_sql(c.w->db, "DROP TABLE v2_storage_reports;"
                           NODUS_V2_STREPS_S19_DDL) == 0,
          "put v2_storage_reports back to the S19 text");
    CHECK(nodus_witness_db_verify_v2s20_shape(c.w) == -1,
          "the S20 verifier sees it"); OK();
    CHECK(chain_reopen(&c) != 0 && c.w->db == NULL,
          "an S20 database with an S19 table is refused, no handle"); OK();
    v2x_chain_close(&c);

    /* (3) a shape in neither text is refused below S20 too */
    CHECK(chain_open_s20(&c, "hf9shape3") == 0, "a real chain at S20");
    CHECK(run_sql(c.w->db, "PRAGMA user_version = 19") == 0, "set 19");
    CHECK(chain_reopen(&c) == 0, "control: reopens at user_version 19");
    CHECK(run_sql(c.w->db, "PRAGMA user_version = 19") == 0, "set 19");
    CHECK(run_sql(c.w->db,
            "DROP TABLE v2_storage_segments;"
            "CREATE TABLE v2_storage_segments (k INTEGER PRIMARY KEY, "
            "root BLOB, published_height INTEGER)") == 0, "tamper segments");
    CHECK(chain_reopen(&c) != 0 && c.w->db == NULL,
          "a tampered table is refused at user_version 19"); OK();
    v2x_chain_close(&c);
    return 0;
}

/* A database ALREADY at S20 skips the rung, so its tree / storage tables
 * are held to the S20 shape by the open-time verifier
 * (nodus_witness_db_verify_v2s20_shape, called from the post-open gate). */
static int test_s20_open_drift(void) {
    static const char *const drift[] = {
        "DROP TABLE v2_tree_nodes",
        "DROP TABLE v2_tree_dirty_pools;"
        "CREATE TABLE v2_tree_dirty_pools (domain_id INTEGER, "
        "pool_id INTEGER)",
        "DROP TABLE v2_tree_shadow_v2_pools",
        "DROP TABLE v2_tree_nodes;"
        "CREATE TABLE v2_tree_nodes (digest BLOB PRIMARY KEY CHECK("
        "typeof(digest)='blob' AND length(digest)=64), rlp BLOB NOT NULL, "
        "refs INTEGER NOT NULL CHECK(refs >= 0)) WITHOUT ROWID",
        "DROP TABLE v2_tree_compwit"
    };
    v2x_chain_t c;
    fixture_t fx;

    /* a database below S20 has nothing to hold (bare fixture, no reopen) */
    CHECK(fx_open(&fx) == 0, "fresh fixture");
    CHECK(nodus_witness_db_verify_v2s20_shape(fx.w) == 0,
          "a database below S20 has nothing to hold"); OK();
    fx_close(&fx);

    /* every post-migration tampering, on a REAL chain (stored genesis
     * document, so the only thing that can refuse its open is the
     * tampering): CONTROL first — the untampered chain holds and
     * reopens — then the drift: the S20 verifier answers -1 on exactly
     * that state, and the open is refused with no handle left */
    for (size_t i = 0; i < sizeof(drift) / sizeof(drift[0]); i++) {
        CHECK(chain_open_s20(&c, "hf9drift") == 0, "a real chain at S20");
        CHECK(nodus_witness_db_verify_v2s20_shape(c.w) == 0,
              "control: the untampered chain holds");
        CHECK(chain_reopen(&c) == 0, "control: and reopens");
        CHECK(run_sql(c.w->db, drift[i]) == 0, "tamper");
        CHECK(nodus_witness_db_verify_v2s20_shape(c.w) == -1,
              "the S20 verifier sees the drift");
        CHECK(chain_reopen(&c) != 0, "the open refuses the drift");
        CHECK(c.w->db == NULL, "...leaving no handle");
        v2x_chain_close(&c);
    }
    OK();

    /* the payee index is part of the shape (every open re-creates it —
     * nodus_witness.c — so only the verifier is asked) */
    CHECK(chain_open_s20(&c, "hf9drift") == 0, "a real chain at S20");
    CHECK(run_sql(c.w->db, "DROP INDEX idx_v2_storage_nodes_payee") == 0,
          "drop the index");
    CHECK(nodus_witness_db_verify_v2s20_shape(c.w) == -1,
          "a missing payee index is drift"); OK();
    v2x_chain_close(&c);
    return 0;
}

int main(void) {
    if (test_fresh() != 0) return 1;
    if (test_s19_to_s20() != 0) return 1;
    if (test_rollback_and_refusal() != 0) return 1;
    if (test_open_shape_check() != 0) return 1;
    if (test_s20_open_drift() != 0) return 1;
    printf("test_hf9_schema: ALL %d checks passed\n", g_checks);
    return 0;
}
