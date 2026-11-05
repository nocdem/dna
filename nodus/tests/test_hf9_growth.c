/**
 * @file nodus/tests/test_hf9_growth.c
 * @brief HF-9 WP4, plan row T-9 (the storage-assignment part) - the growth
 *        rule: per-boundary work grows only with the records the boundary
 *        changes, never with the history.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  Two chains are built from the same code and differ ONLY in the size of
 *  their storage history: S = 25 contiguous segments / 100 RELEASED nodes,
 *  and S = 25 000 contiguous segments / 100 000 RELEASED nodes (the plan's
 *  1e2 -> 1e5 range; with R = 4 copies the production transition derives
 *  S x 4 assignment rows: 100 and 100 000). The history is a state
 *  production can produce (Sol re-verify rows 2 and 4):
 *   - registry: ACTIVE members and RELEASED nodes whose node_fp is
 *     SHA3-512 of their own 2 592-byte key (the registry loader's rule,
 *     nodus_witness_roots_v2.c "the key IS the hash of the key material it
 *     names");
 *   - segments: k = 1..S contiguous, segment k published at the boundary
 *     k x 24 E + 2 E (st_publish: due(k) = k x P + DNAC_STORAGE_SEGMENT_
 *     DELAY_EPOCHS x E, never earlier; DNA_V2_SEGMENT_BLOCKS = P = 24 E),
 *     the last at the last generation-5 boundary H2 = S x P + 2 E;
 *   - assignments: NOT planted - the production generation-6 transition
 *     (E-s2, nodus_witness_storage_gen6_transition) derives the rendezvous
 *     rows of every published segment, so they match the segments by
 *     construction.
 *  Then the chain runs the real generation-6 boundary procedure's exported
 *  steps - the prune (nodus_witness_storage_prune) and the freeze
 *  (nodus_witness_storage_freeze_gen6) - in the real order, at consecutive
 *  boundaries (a skipped boundary is a FAULT):
 *   B1       the first generation-6 boundary (transition, not compared);
 *   B1 + E   an EVENT boundary (an arrival, operator exception D11): every
 *            published segment is visited once - segments_visited == S,
 *            counted SEPARATELY and not compared across sizes;
 *   B1 + 2E  an ORDINARY boundary (no membership change, no new segment);
 *   H2 + 24E the boundary at which segment S + 1 falls due: one new segment.
 *  Asserted: every counter of g_nodus_storage_work (registry rows read,
 *  segments visited, assignment rows read / written, scores computed) is
 *  EQUAL on the two chains for the ordinary and for the publication
 *  boundary, and non-zero where the path must touch it (the false-pass
 *  guard: counters not wired to the real path); the registry status query's
 *  virtual-machine steps are within 64 (indexed: drifted 288 -> 289; a scan
 *  adds one step per RELEASED row) with the positive control that the same
 *  query with the index disabled (+status) steps at least 10 000 more; and
 *  the TOTAL virtual-machine instructions of prune + freeze (progress
 *  handler, period 1) differ between the chains by less than a tenth of
 *  one instruction per row of added history - a scan of any history table
 *  adds at least one per row.
 *  The mutation "visit every segment on an ordinary boundary" makes
 *  segments_visited and the instruction count grow with S and fails the
 *  equality.
 *
 * ── WHAT IT DOES NOT COVER ──────────────────────────────────────────────
 *  The settlement, the release and the publication step of the boundary are
 *  static functions of nodus_witness_v2_storage.c run only inside
 *  nodus_witness_storage_boundary_apply, which needs a genesis-seeded SYSTEM
 *  runtime: they are measured on real blocks by test_cmt_app's
 *  hybrid_growth_probe (boundaries 2E and 3E, registry history to 1e5, a
 *  whole-block instruction count) - there with no segment history, because
 *  a valid segment needs 24 E real blocks. The settlement payout (signed
 *  reports, pool 1) is not run. The ordinary-block half (trie nodes loaded
 *  by the flush of ONE changed key, nodus_witness_v2_trie.c ts_get) is
 *  measured on a tokens leg of 100 and of 5 000 rows by trie_probe(): the
 *  path-depth BOUND (<= 131 nodes, plan 5.6), not equality, because the
 *  depth grows with log16(rows); the flush is driven directly there; the
 *  real-block version is in test_cmt_app.
 *
 * ── FLAGS ───────────────────────────────────────────────────────────────
 *  register_witness_test; EVM runtime only. No fault injection, no
 *  environment; DNAC_EPOCH_LENGTH of the build (heights are computed from
 *  it). Leaves /tmp/test_hf9_growth_XXXXXX (removed at exit); the large
 *  chain writes about 300 MB (100 000 keys of 2 592 bytes) there.
 *
 * ── HOW IT CAN FALSELY PASS OR SKIP ─────────────────────────────────────
 *  Equal counters on a path that does no work are caught by the non-zero
 *  asserts. Segment roots are SHA3-512 of a counter, not of blocks (no
 *  v2_blocks exist), so nothing here proves root derivation - the freeze
 *  never reads them. The growth claim covers the tables this fixture
 *  grows: registry, segments, assignments (and sets / members not at all:
 *  one frozen set per boundary is the production shape). An instruction
 *  count differing by less than the tenth passes a scan of a table that did
 *  not grow.
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
#include <inttypes.h>
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
#define P_LEN  ((uint64_t)DNA_V2_SEGMENT_BLOCKS)       /* 24 E */
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

/* `n` RELEASED registry nodes with valid identities: node_fp = SHA3-512 of
 * the node's own 2 592-byte key; keys distinct (counter in bytes 16..19);
 * all other columns inside the loader's ranges. Production produces such
 * rows (an exited node); the UTXO its release created is spent after the
 * 12-epoch lock, so none is planted. */
static int plant_released(unsigned n) {
    sqlite3_stmt *st = NULL;
    uint8_t *pk = malloc(DNAC_PUBKEY_SIZE);
    int rc = SQLITE_DONE;
    if (!pk) return -1;
    if (sqlx("BEGIN") != 0 ||
        sqlite3_prepare_v2(g_w->db,
            "INSERT INTO v2_storage_nodes (node_fp, node_pk, payee_fp, "
            "bond, status, registered_height, exit_height, fail_streak, "
            "grace_until) VALUES (?1, ?2, ?3, 1000, 3, 1, 2, 0, 0)", -1, &st,
            NULL) != SQLITE_OK) {
        free(pk);
        return -1;
    }
    for (unsigned i = 0; i < n && rc == SQLITE_DONE; i++) {
        uint8_t fp[64], py[64];
        memset(pk, 0xA5, DNAC_PUBKEY_SIZE);
        memcpy(pk, "hf9-wp4-growth-r", 16);
        for (int b = 0; b < 4; b++) pk[16 + b] = (uint8_t)(i >> (8 * (3 - b)));
        if (qgp_sha3_512(pk, DNAC_PUBKEY_SIZE, fp) != 0 ||
            qgp_sha3_512(fp, 64, py) != 0) { rc = SQLITE_ERROR; break; }
        sqlite3_reset(st);
        sqlite3_bind_blob(st, 1, fp, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 2, pk, DNAC_PUBKEY_SIZE, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 3, py, 64, SQLITE_TRANSIENT);
        rc = sqlite3_step(st);
    }
    sqlite3_finalize(st);
    free(pk);
    if (rc != SQLITE_DONE) { (void)sqlx("ROLLBACK"); return -1; }
    return sqlx("COMMIT");
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

static int prog_cb(void *p) {
    (*(uint64_t *)p)++;
    return 0;                      /* never interrupt */
}

/* one generation-6 boundary in the real order (prune, then freeze); the
 * counters of that prune + freeze alone in *wk and their TOTAL SQLite
 * virtual-machine instructions in *ops (either may be NULL) */
static int freeze(uint64_t B, unsigned n_new_seg, nodus_storage_work_t *wk,
                  uint64_t *ops) {
    for (unsigned i = 0; i < n_new_seg; i++)
        if (seg_put(g_nseg + 1, B) != 0) return -1;
    nodus_storage_boundary_t out;
    memset(&out, 0, sizeof(out));
    out.n_published = n_new_seg;
    uint64_t n = 0;
    if (sqlx("BEGIN IMMEDIATE") != 0) return -1;
    memset(&g_nodus_storage_work, 0, sizeof(g_nodus_storage_work));
    sqlite3_progress_handler(g_w->db, 1, prog_cb, &n);
    int rc = nodus_witness_storage_prune(g_w, B, 1);
    if (rc == 0)
        rc = nodus_witness_storage_freeze_gen6(
                 g_w, B, 4, DNA_V2_STORAGE_SET_LIMIT_GEN6, &out);
    sqlite3_progress_handler(g_w->db, 0, NULL, NULL);
    if (wk) *wk = g_nodus_storage_work;
    if (ops) *ops = n;
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

typedef struct {
    nodus_storage_work_t ev, ord, pub;     /* event / ordinary / publication */
    uint64_t             ord_ops, pub_ops; /* prune + freeze instructions    */
    long long            steps[2];         /* status query: indexed, scan    */
    unsigned             nseg;             /* segments before the event      */
} scale_t;

/* One chain: `s_seg` valid contiguous segments, `n_rel` RELEASED nodes,
 * 10 ACTIVE members at H2, the production transition at the edge, then the
 * boundaries described in the header. 0 / 1 (a failed CHECK). */
static int run_scale(unsigned s_seg, unsigned n_rel, scale_t *r) {
    const uint64_t delay = (uint64_t)DNAC_STORAGE_SEGMENT_DELAY_EPOCHS * E_LEN;
    const uint64_t H2 = (uint64_t)s_seg * P_LEN + delay;    /* last gen-5 B */
    nodus_storage_work_t wk;
    memset(r, 0, sizeof(*r));
    g_nseg = 0;
    g_w = calloc(1, sizeof(*g_w));
    CHECK(g_w != NULL, "alloc");
    snprintf(g_dir, sizeof(g_dir), "/tmp/test_hf9_growth_XXXXXX");
    CHECK(mkdtemp(g_dir) != NULL, "tmpdir");
    snprintf(g_w->data_path, sizeof(g_w->data_path), "%s", g_dir);
    uint8_t c16[16];
    memset(c16, 0x46, sizeof(c16));
    CHECK(nodus_witness_create_chain_db(g_w, c16) == 0 &&
          nodus_witness_db_migrate_v2s20(g_w) == 0, "fixture");

    /* history: set(H2) of 10 members, S contiguous segments k published
     * at k x P + 2E (the last at H2), the RELEASED nodes */
    CHECK(plant_set(H2, 10) == 0, "set(H2)");
    for (unsigned i = 0; i < 10; i++) CHECK(reg_put(i) == 0, "registry");
    CHECK(plant_released(n_rel) == 0, "released registry history");
    CHECK(sqlx("BEGIN") == 0, "begin");
    for (unsigned k = 1; k <= s_seg; k++)
        CHECK(seg_put(k, (uint64_t)k * P_LEN + delay) == 0, "segment");
    CHECK(sqlx("COMMIT") == 0, "commit");
    CHECK(cc_row(DNAC_CFG_RULESET_GEN_ROLES, 1, 1, 1) == 0 &&
          cc_row(DNAC_CFG_RULESET_GEN_TRIE, 1, H2 + 2, 2) == 0, "params");
    /* the edge block A - 1 = H2 + 1 derives the assignment rows of every
     * published segment (E-s2): the history the boundaries then ride on */
    CHECK(sqlx("BEGIN IMMEDIATE") == 0 &&
          nodus_witness_storage_gen6_transition(g_w, H2 + 1) == 0 &&
          sqlx("COMMIT") == 0, "edge");
    r->nseg = g_nseg;

    uint64_t B = H2 + E_LEN;
    CHECK(freeze(B, 0, &wk, NULL) == 0, "B1");

    /* an EVENT boundary (an arrival), counted SEPARATELY */
    CHECK(reg_put(10) == 0, "an arrival");
    B += E_LEN;
    CHECK(freeze(B, 0, &r->ev, NULL) == 0, "event boundary");
    CHECK(r->ev.segments_visited == g_nseg,
          "an event boundary visits every published segment once (D11)");
    CHECK(r->ev.assign_rows_read > 0 && r->ev.assign_rows_written > 0,
          "the assignment-row counters are wired to the real path (they "
          "are 0 on an ordinary boundary, so the event boundary proves "
          "them non-zero)");

    /* an ordinary boundary: same membership, no new segment */
    B += E_LEN;
    CHECK(freeze(B, 0, &r->ord, &r->ord_ops) == 0, "ordinary boundary");
    CHECK(r->ord.registry_rows_read >= 11 && r->ord.registry_vm_steps > 0,
          "the ordinary boundary reads the ACTIVE members through the "
          "status index (wired)");
    CHECK(r->ord.segments_visited == 0 && r->ord.scores_computed == 0 &&
          r->ord.assign_rows_written == 0 && r->ord.assign_rows_read == 0,
          "an ordinary boundary with no new segment does no assignment "
          "work");

    /* consecutive boundaries up to the one at which segment S + 1 is due:
     * H2 + 24E = (S + 1) x P + 2E */
    while (B + E_LEN < H2 + P_LEN) {
        B += E_LEN;
        CHECK(freeze(B, 0, NULL, NULL) == 0, "boundary");
    }
    B += E_LEN;
    CHECK(B == (uint64_t)(s_seg + 1) * P_LEN + delay,
          "the publication boundary is when segment S + 1 falls due");
    CHECK(freeze(B, 1, &r->pub, &r->pub_ops) == 0, "publication boundary");
    CHECK(r->pub.segments_visited == 1 && r->pub.assign_rows_written == 4 &&
          r->pub.scores_computed >= 11,
          "the publication boundary visits exactly the 1 new segment, "
          "writes R = 4 rows and scores the eligible members (wired)");

    /* the status query: indexed versus the control scan, on this registry */
    {
        static const char *const q[2] = {
            "SELECT node_fp FROM v2_storage_nodes WHERE status = 1",
            /* NOT INDEXED is not honoured on this WITHOUT ROWID table
             * (SQLite 3.40.1); the unary plus on the column disables the
             * index instead ("SCAN v2_storage_nodes") */
            "SELECT node_fp FROM v2_storage_nodes WHERE +status = 1 "
            "ORDER BY node_fp ASC" };
        for (int i = 0; i < 2; i++) {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(g_w->db, q[i], -1, &st, NULL)
                  == SQLITE_OK, "control query");
            while (sqlite3_step(st) == SQLITE_ROW) { }
            r->steps[i] = sqlite3_stmt_status(st, SQLITE_STMTSTATUS_VM_STEP, 0);
            sqlite3_finalize(st);
        }
    }
    sqlite3_close(g_w->db);
    free(g_w);
    g_w = NULL;
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

    static scale_t small, big;
    CHECK(run_scale(25, 100, &small) == 0, "chain with 25 segments");
    CHECK(run_scale(25000, 100000, &big) == 0,
          "chain with 25 000 segments");
    CHECK(small.ev.segments_visited == 25 && big.ev.segments_visited == 25000,
          "the event boundary's visit count follows the segment count "
          "(counted separately)");
    fprintf(stderr, "T-9 ord: 1e2 reg_rows %" PRIu64 " vm %" PRIu64
            " ops %" PRIu64 " | 1e5 reg_rows %" PRIu64 " vm %" PRIu64
            " ops %" PRIu64 "\n", small.ord.registry_rows_read,
            small.ord.registry_vm_steps, small.ord_ops,
            big.ord.registry_rows_read, big.ord.registry_vm_steps,
            big.ord_ops);
    fprintf(stderr, "T-9 pub: 1e2 ops %" PRIu64 " | 1e5 ops %" PRIu64 "\n",
            small.pub_ops, big.pub_ops);

    /* equal in every counter (ordinary and publication boundary) */
    CHECK(small.ord.registry_rows_read == big.ord.registry_rows_read &&
          small.ord.segments_visited == big.ord.segments_visited &&
          small.ord.assign_rows_read == big.ord.assign_rows_read &&
          small.ord.assign_rows_written == big.ord.assign_rows_written &&
          small.ord.scores_computed == big.ord.scores_computed,
          "the work of an ordinary boundary does not depend on the "
          "history: every counter equal after the history grew from 25 to "
          "25 000 segments, 100 to 100 000 assignment rows and 100 to "
          "100 000 RELEASED nodes");
    CHECK(small.pub.registry_rows_read == big.pub.registry_rows_read &&
          small.pub.segments_visited == big.pub.segments_visited &&
          small.pub.assign_rows_read == big.pub.assign_rows_read &&
          small.pub.assign_rows_written == big.pub.assign_rows_written &&
          small.pub.scores_computed == big.pub.scores_computed,
          "the work of a publication boundary (one new segment) does not "
          "depend on the history either");
    /* work EXAMINED, not rows returned: SQLite's virtual-machine step count
     * of the registry status query (registry_vm_steps) - a BOUND, not
     * equality (288 -> 289 drift measured when rows follow the ACTIVE
     * range); a scan steps once per registry row, 100 000 more here */
    CHECK(big.ord.registry_vm_steps <= small.ord.registry_vm_steps + 64 &&
          small.ord.registry_vm_steps <= big.ord.registry_vm_steps + 64 &&
          big.pub.registry_vm_steps <= small.pub.registry_vm_steps + 64 &&
          small.pub.registry_vm_steps <= big.pub.registry_vm_steps + 64,
          "the registry status query examines the same work (within 64 VM "
          "steps) at both history sizes");
    CHECK(big.steps[0] > 0 && big.steps[1] >= big.steps[0] + 10000,
          "control: the real scan (+status) steps at least 10 000 more "
          "than the indexed query - the counter can see the difference");
    /* the total work of prune + freeze, every statement counted */
    {
        const uint64_t added = (uint64_t)(25000 - 25) * 4u + (100000u - 100u);
        const uint64_t d1 = small.ord_ops > big.ord_ops
                                ? small.ord_ops - big.ord_ops
                                : big.ord_ops - small.ord_ops;
        const uint64_t d2 = small.pub_ops > big.pub_ops
                                ? small.pub_ops - big.pub_ops
                                : big.pub_ops - small.pub_ops;
        CHECK(small.ord_ops > 0 && big.ord_ops > 0 &&
              small.pub_ops > 0 && big.pub_ops > 0,
              "the instruction counter is wired (non-zero)");
        CHECK(d1 < added / 10 && d2 < added / 10,
              "prune + freeze run the same number of VM instructions (to "
              "within a tenth of one per added history row) at both sizes");
    }

    /* the ordinary-block half of T-9: trie nodes loaded by the flush of
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
