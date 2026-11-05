/**
 * @file nodus/tests/test_storage_hrw.c
 * @brief HF-9 WP4, plan row T-7 - the rendezvous storage assignment of plan
 *        docs/plans/approved/2026-11-04-hf9.md section 8 over a scratch S20
 *        chain database: the edge's storage transition E-s1..E-s3
 *        (nodus_witness_storage_gen6_transition) and the generation-6
 *        freeze (nodus_witness_storage_freeze_gen6) boundary by boundary.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  After the edge step and after EVERY boundary B >= B1, independently of
 *  the engine's own bookkeeping (the model below is computed from the
 *  RELATIONS with the production selector dna_v2_segment_holders_hrw - the
 *  one full-recompute reference, itself pinned to the independent oracle by
 *  test_hf9_kat - and the existing XOR selector nodus_witness_storage_
 *  holders):
 *   R  the current rows of v2_storage_assign of every segment equal
 *      holders_hrw(k, eligible(B), R(B)) (min(R, eligible) holders);
 *   H  v2_storage_held equals the count of current rows per member, and a
 *      member without a row has no held row;
 *   U  v2_storage_member_epoch(B, m).held_union = |cur(m) U prev(m)| and
 *      .n_new = |{k published <= B - E : m in cur(k) \ prev(k)}| for the
 *      members of set(B) only (K9a cutoff), prev = the previous boundary's
 *      model relation, or at B1 XOR(set(H2)) over the segments published at
 *      or before H2;
 *   S  the basis equals eligible(B), the state is (R(B), B, xfer 0), and the
 *      one-use table is DROPPED after B1 (plan 8.6) and the per-open
 *      re-check (db_s20_reseed) accepts the database without it.
 *  Cases (each is asserted to CHANGE at least one holder - the false-pass
 *  guard of the plan's T-7 row): B1 without an event (the E-s3 table path),
 *  an ordinary boundary with a new segment, one arrival (join rule), TWO
 *  arrivals with segments where both enter the top R (the join-rule case:
 *  comparing each arrival against the stale R-th score would be wrong), a
 *  departure of holders, a fail_streak crossing up and back down, R 4 -> 6
 *  -> 4 and R 4 -> 16 -> 4 through the retained maintenance (18 eligible
 *  members, exactly 16 holders per segment at R = 16; param 25 rows), B1 WITH an event (rows maintained against the E-s2
 *  rows, counts against XOR(set(H2)) - two separate CHECK groups, D17
 *  report 2 finding 4), a chain with no set(H2) (B1 is an ordinary first
 *  freeze, which runs through the event path: six arrivals against an empty
 *  basis), fewer eligible members than R (3 members, R 4), and 1024
 *  members (the generation-6 cap) against the R = 4 model.
 *  G  (every boundary) the K9 grace written into the frozen set equals
 *  max(old, B + n_new x E) of the model.
 *  Also: E-s1 writes the XOR union counts of the two epochs settled at B1
 *  and B1 + E (model: the XOR relation, not the walk); a stale or missing
 *  assignment state is a FAULT; param 25 reader (default 4, a stored value
 *  outside [4, 16] is a fault); the freeze refuses a member count above the
 *  limit it is given.
 *
 * ── WHAT IT DOES NOT PROVE ──────────────────────────────────────────────
 *  No block is applied: the edge's order and atomicity are test_hf9_edge's,
 *  the block path (settlement weights = P x held_union against real
 *  reports, pay) is T-13 / T-15's and the existing test_storage_b2 section
 *  D for generation 4; T-7 cannot see the leg roots (no flush runs). The
 *  generation-<=5 selector stays pinned by test_storage_segment.c (the
 *  three-holder case, unchanged) and archive_reward_kat.json through
 *  test_storage_b2 (unchanged); this test does not replay them.
 *
 * ── FLAGS ───────────────────────────────────────────────────────────────
 *  register_witness_test (NODUS_WITNESS_INTERNAL_API). Segments and sets
 *  are seeded directly, so the test is epoch-length agnostic (it uses
 *  DNAC_EPOCH_LENGTH as given; the plan's short-epoch flag is not required
 *  and is not claimed). No environment, no fault injection.
 *
 * ── LEAVES BEHIND ───────────────────────────────────────────────────────
 *  /tmp/test_storage_hrw_XXXXXX per fixture, removed at exit (a crash
 *  leaves it).
 *
 * ── HOW IT CAN FALSELY PASS OR SKIP ─────────────────────────────────────
 *  - The model uses the same selector function as production (that is the
 *    point: one reference); a wrong selector is test_hf9_kat's to catch.
 *  - The "holder changed" assertions guard a case that changes nothing.
 *  - The join-rule case asserts, from the model and before the engine
 *    runs, that at least one segment has BOTH arrivals above the old 4th
 *    best score. The fixtures are deterministic (member keys, segment
 *    roots), and the cases were re-derived outside the C code with
 *    Python hashlib.sha3_512 (author's check, 2026-11-05, same layouts):
 *    with 12 segments at that step both arrivals beat the old 4th-best
 *    score of 1 segment (both in the new top 4 of 0); every other "changes
 *    a holder" case changes 1 to 14 segments. A changed fixture needs the
 *    same re-derivation - the guards fail loudly, never pass silently.
 *  - Member keys are fixtures (2592 bytes, fp = SHA3-512), the registry
 *    row checks of the loader apply; a different key length would be
 *    refused, not silently accepted.
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_storage.h"
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
        fprintf(stderr, "CHECK failed at %s:%d: %s [%s]\n", __FILE__, \
                __LINE__, (msg), g_ctx); \
        return 1; \
    } \
    g_checks++; \
} while (0)

static int g_checks = 0;
static char g_ctx[96] = "(setup)";

#define E_LEN   ((uint64_t)DNAC_EPOCH_LENGTH)
#define NMEM    20u      /* member fixtures (18 eligible at the R = 16 case) */
#define NSEG    20u      /* segment fixtures                                */
#define RMAX    DNA_V2_STORAGE_HOLDERS_CAP

/* ── fixture ─────────────────────────────────────────────────────────── */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
} fx_t;

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

static int sqlx(nodus_witness_t *w, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(w->db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL failed: %s [%s]\n", err ? err : "?", sql);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static long long q1(nodus_witness_t *w, const char *sql) {
    sqlite3_stmt *st = NULL;
    long long v = -1;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

static uint64_t g_grace[NMEM];             /* the model of grace_until    */
static int fx_open(fx_t *fx) {
    memset(fx, 0, sizeof(*fx));
    memset(g_grace, 0, sizeof(g_grace));
    fx->w = calloc(1, sizeof(*fx->w));      /* multi-MB - ALWAYS heap */
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_storage_hrw_XXXXXX");
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    uint8_t chain16[16];
    memset(chain16, 0x44, sizeof(chain16));
    if (nodus_witness_create_chain_db(fx->w, chain16) != 0 ||
        nodus_witness_db_migrate_v2s20(fx->w) != 0) {
        rmrf(fx->dir);
        free(fx->w);
        fx->w = NULL;
        return -1;
    }
    return 0;
}

static void fx_close(fx_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) sqlite3_close(fx->w->db);
    free(fx->w);
    fx->w = NULL;
    rmrf(fx->dir);
}

static int cc_row(nodus_witness_t *w, unsigned param, uint64_t value,
                  uint64_t effective, uint64_t nonce) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
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
    w->chain_config_cache_warm = false;
    return rc == SQLITE_DONE ? 0 : -1;
}

/* ── members and segments ────────────────────────────────────────────── */

static uint8_t g_pk[NMEM][DNAC_PUBKEY_SIZE];
static uint8_t g_fp[NMEM][64];

static int members_init(void) {
    for (unsigned i = 0; i < NMEM; i++) {
        for (size_t j = 0; j < DNAC_PUBKEY_SIZE; j++)
            g_pk[i][j] = (uint8_t)(i * 37u + j * 11u + 5u);
        g_pk[i][0] = (uint8_t)i;
        g_pk[i][1] = 0xA7;
        if (qgp_sha3_512(g_pk[i], DNAC_PUBKEY_SIZE, g_fp[i]) != 0) return -1;
    }
    return 0;
}

static int member_of(const uint8_t fp[64]) {
    for (unsigned i = 0; i < NMEM; i++)
        if (memcmp(g_fp[i], fp, 64) == 0) return (int)i;
    return -1;
}

/* status 1 ACTIVE / 2 EXITING; fs the fail_streak. An existing row keeps
 * its grace_until (the freeze's K9 update writes it); a new row starts 0. */
static int reg_put(nodus_witness_t *w, unsigned i, int status, unsigned fs) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "UPDATE v2_storage_nodes SET status = ?3, exit_height = ?4, "
            "fail_streak = ?5 WHERE node_fp = ?1", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, g_fp[i], 64, SQLITE_STATIC);
    sqlite3_bind_int(st, 3, status);
    sqlite3_bind_int(st, 4, status == 1 ? 0 : 1);
    sqlite3_bind_int(st, 5, (int)fs);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;
    if (sqlite3_changes(w->db) == 1) return 0;
    st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_storage_nodes (node_fp, node_pk, payee_fp, "
            "bond, status, registered_height, exit_height, fail_streak, "
            "grace_until) VALUES (?1, ?2, zeroblob(64), 1000, ?3, 1, ?4, "
            "?5, 0)", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, g_fp[i], 64, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, g_pk[i], DNAC_PUBKEY_SIZE, SQLITE_STATIC);
    sqlite3_bind_int(st, 3, status);
    sqlite3_bind_int(st, 4, status == 1 ? 0 : 1);
    sqlite3_bind_int(st, 5, (int)fs);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static void seg_root(unsigned k, uint8_t out[64]) {
    uint8_t pre[16] = "hf9-wp4-seg....";
    pre[12] = (uint8_t)k;
    qgp_sha3_512(pre, sizeof(pre), out);
}

static int seg_put(nodus_witness_t *w, unsigned k, uint64_t pub) {
    uint8_t r[64];
    seg_root(k, r);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "INSERT INTO v2_storage_segments (k, "
                           "root, published_height) VALUES (?1, ?2, ?3)",
                           -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(st, 1, (int)k);
    sqlite3_bind_blob(st, 2, r, 64, SQLITE_STATIC);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)pub);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* a generation-<=5 frozen set at H of the member ids in `ids` (any
 * order), fail_streak 0, grace 0 - the history the edge transitions from */
static int plant_set(nodus_witness_t *w, uint64_t H, const unsigned *ids,
                     size_t n) {
    uint8_t fps[NMEM][64];
    size_t c = 0;
    for (size_t i = 0; i < n; i++) memcpy(fps[c++], g_fp[ids[i]], 64);
    for (size_t i = 1; i < c; i++)               /* insertion sort ASC */
        for (size_t j = i; j > 0 && memcmp(fps[j - 1], fps[j], 64) > 0; j--) {
            uint8_t t[64];
            memcpy(t, fps[j], 64);
            memcpy(fps[j], fps[j - 1], 64);
            memcpy(fps[j - 1], t, 64);
        }
    uint8_t sh[64];
    if (dna_v2_storage_set_hash(H, (const uint8_t (*)[64])fps, c, sh) != 0)
        return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "INSERT INTO v2_storage_sets (epoch_start, "
                           "set_hash, member_count) VALUES (?1, ?2, ?3)", -1,
                           &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)H);
    sqlite3_bind_blob(st, 2, sh, 64, SQLITE_STATIC);
    sqlite3_bind_int(st, 3, (int)c);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;
    for (size_t i = 0; i < c; i++) {
        st = NULL;
        if (sqlite3_prepare_v2(w->db, "INSERT INTO v2_storage_set_members "
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

/* ── the model: relations computed from the selector functions ───────── */

typedef struct {
    size_t  n[NSEG + 1];
    uint8_t fp[NSEG + 1][RMAX][64];      /* each list sorted by fp ASC     */
} rel_t;

static uint64_t g_pub[NSEG + 1];          /* published_height of segment k  */
static unsigned g_nseg;                   /* segments 1..g_nseg exist       */

static void sort_fps(uint8_t (*l)[64], size_t n) {
    for (size_t i = 1; i < n; i++)
        for (size_t j = i; j > 0 && memcmp(l[j - 1], l[j], 64) > 0; j--) {
            uint8_t t[64];
            memcpy(t, l[j], 64);
            memcpy(l[j], l[j - 1], 64);
            memcpy(l[j - 1], t, 64);
        }
}

static int in_rel(const rel_t *r, unsigned k, const uint8_t fp[64]) {
    for (size_t i = 0; i < r->n[k]; i++)
        if (memcmp(r->fp[k][i], fp, 64) == 0) return 1;
    return 0;
}

/* the rendezvous relation of `set` over segments 1..nseg */
static int rel_hrw(const nodus_storage_set_t *set, size_t R, rel_t *out) {
    memset(out, 0, sizeof(*out));
    for (unsigned k = 1; k <= g_nseg; k++) {
        uint8_t root[64], a[64];
        size_t idx[RMAX], nh = 0;
        seg_root(k, root);
        if (dna_v2_segment_assign_key(root, a) != 0 ||
            dna_v2_segment_holders_hrw(a, (const uint8_t (*)[64])set->fps,
                                       set->fail_streak, set->count, R, idx,
                                       &nh) != 0)
            return -1;
        out->n[k] = nh;
        for (size_t i = 0; i < nh; i++) memcpy(out->fp[k][i], set->fps[idx[i]], 64);
        sort_fps(out->fp[k], nh);
    }
    return 0;
}

/* the XOR relation of `set` over segments published at or before `maxpub` */
static int rel_xor(const nodus_storage_set_t *set, uint64_t maxpub,
                   rel_t *out) {
    memset(out, 0, sizeof(*out));
    for (unsigned k = 1; k <= g_nseg; k++) {
        if (g_pub[k] > maxpub) continue;
        uint8_t root[64], hf[DNA_V2_STORAGE_HOLDERS][64];
        size_t nh = 0;
        seg_root(k, root);
        if (nodus_witness_storage_holders(set, root, hf, &nh) != 0) return -1;
        out->n[k] = nh;
        for (size_t i = 0; i < nh; i++) memcpy(out->fp[k][i], hf[i], 64);
        sort_fps(out->fp[k], nh);
    }
    return 0;
}

static int rel_changed(const rel_t *a, const rel_t *b) {
    int c = 0;
    for (unsigned k = 1; k <= g_nseg; k++) {
        if (a->n[k] != b->n[k]) { c++; continue; }
        for (size_t i = 0; i < a->n[k]; i++)
            if (memcmp(a->fp[k][i], b->fp[k][i], 64) != 0) { c++; break; }
    }
    return c;
}

/* ── reading the engine's tables ─────────────────────────────────────── */

static int cur_rows(nodus_witness_t *w, unsigned k, uint8_t (*fp)[64],
                    size_t *n) {
    sqlite3_stmt *st = NULL;
    *n = 0;
    if (sqlite3_prepare_v2(w->db, "SELECT node_fp FROM v2_storage_assign "
                           "WHERE k = ?1 AND to_h IS NULL ORDER BY node_fp",
                           -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(st, 1, (int)k);
    while (sqlite3_step(st) == SQLITE_ROW) {
        if (*n >= RMAX || sqlite3_column_bytes(st, 0) != 64) {
            sqlite3_finalize(st);
            return -1;
        }
        memcpy(fp[(*n)++], sqlite3_column_blob(st, 0), 64);
    }
    sqlite3_finalize(st);
    return 0;
}

static long long count_member_rows(nodus_witness_t *w, const uint8_t fp[64]) {
    sqlite3_stmt *st = NULL;
    long long v = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT COUNT(*) FROM v2_storage_assign "
                           "WHERE node_fp = ?1 AND to_h IS NULL", -1, &st,
                           NULL) == SQLITE_OK) {
        sqlite3_bind_blob(st, 1, fp, 64, SQLITE_STATIC);
        if (sqlite3_step(st) == SQLITE_ROW) v = sqlite3_column_int64(st, 0);
    }
    sqlite3_finalize(st);
    return v;
}

static long long held_of(nodus_witness_t *w, const uint8_t fp[64]) {
    sqlite3_stmt *st = NULL;
    long long v = 0;
    if (sqlite3_prepare_v2(w->db, "SELECT held FROM v2_storage_held WHERE "
                           "node_fp = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, fp, 64, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

static int me_row(nodus_witness_t *w, uint64_t H, const uint8_t fp[64],
                  long long *hu, long long *nn) {
    sqlite3_stmt *st = NULL;
    int found = 0;
    if (sqlite3_prepare_v2(w->db, "SELECT held_union, n_new FROM "
                           "v2_storage_member_epoch WHERE epoch_start = ?1 "
                           "AND node_fp = ?2", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)H);
    sqlite3_bind_blob(st, 2, fp, 64, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) {
        *hu = sqlite3_column_int64(st, 0);
        *nn = sqlite3_column_int64(st, 1);
        found = 1;
    }
    sqlite3_finalize(st);
    return found;
}

/* ── the per-boundary checks ─────────────────────────────────────────── */

/* R + H + S groups for boundary B against the model `cur` of `set` */
static int check_rows_held_state(nodus_witness_t *w, uint64_t B, size_t R,
                                 const nodus_storage_set_t *set,
                                 const rel_t *cur, int is_b1) {
    for (unsigned k = 1; k <= g_nseg; k++) {
        uint8_t rows[RMAX][64];
        size_t nr = 0;
        CHECK(cur_rows(w, k, rows, &nr) == 0, "rows readable");
        CHECK(nr == cur->n[k], "R: row count = min(R, eligible)");
        for (size_t i = 0; i < nr; i++)
            CHECK(memcmp(rows[i], cur->fp[k][i], 64) == 0,
                  "R: the rows equal holders_hrw over eligible(B)");
    }
    for (unsigned m = 0; m < NMEM; m++) {
        long long cnt = 0;
        for (unsigned k = 1; k <= g_nseg; k++)
            cnt += in_rel(cur, k, g_fp[m]);
        CHECK(count_member_rows(w, g_fp[m]) == cnt, "H: rows per member");
        CHECK(held_of(w, g_fp[m]) == cnt,
              "H: v2_storage_held = current rows (no row at 0)");
    }
    /* S: basis, state */
    long long nb = q1(w, "SELECT COUNT(*) FROM v2_storage_assign_basis");
    long long ne = 0;
    for (uint32_t i = 0; i < set->count; i++) {
        if (set->fail_streak[i] >= DNA_V2_STORAGE_FAIL_LIMIT) continue;
        ne++;
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(w->db, "SELECT COUNT(*) FROM "
              "v2_storage_assign_basis WHERE node_fp = ?1", -1, &st, NULL)
              == SQLITE_OK, "basis query");
        sqlite3_bind_blob(st, 1, set->fps[i], 64, SQLITE_STATIC);
        CHECK(sqlite3_step(st) == SQLITE_ROW &&
              sqlite3_column_int(st, 0) == 1, "S: basis holds the eligible");
        sqlite3_finalize(st);
    }
    CHECK(nb == ne, "S: basis = eligible(B), nothing else");
    CHECK(q1(w, "SELECT copies FROM v2_storage_assign_state WHERE id = 1")
              == (long long)R &&
          q1(w, "SELECT boundary FROM v2_storage_assign_state WHERE id = 1")
              == (long long)B &&
          q1(w, "SELECT xfer FROM v2_storage_assign_state WHERE id = 1") == 0,
          "S: state = (R(B), B, xfer 0)");
    if (is_b1) {
        CHECK(q1(w, "SELECT COUNT(*) FROM sqlite_master WHERE type = "
                    "'table' AND name = 'v2_storage_xfer_diff'") == 0,
              "S: the one-use table is DROPPED after B1 (plan 8.6)");
        CHECK(nodus_witness_db_s20_reseed(w) == 0,
              "S: the per-open re-check accepts the database without the "
              "one-use table (state xfer = 0)");
    }
    return 0;
}

/* U group: held_union / n_new against the relations */
static int check_union(nodus_witness_t *w, uint64_t B,
                       const nodus_storage_set_t *set, const rel_t *cur,
                       const rel_t *prev) {
    for (uint32_t i = 0; i < set->count; i++) {
        long long hu = 0, nn = 0, want_hu = 0, want_nn = 0;
        for (unsigned k = 1; k <= g_nseg; k++) {
            const int c = in_rel(cur, k, set->fps[i]);
            const int old = g_pub[k] + E_LEN <= B;      /* published <= B - E */
            const int p = old && in_rel(prev, k, set->fps[i]);
            if (c || p) want_hu++;
            if (old && c && !p) want_nn++;
        }
        CHECK(me_row(w, B, set->fps[i], &hu, &nn) == 1,
              "U: a member_epoch row for every member of set(B)");
        CHECK(hu == want_hu, "U: held_union = |cur U prev| from the relations");
        CHECK(nn == want_nn,
              "U: n_new = |{k published <= B - E : cur \\ prev}|");
        /* G: the K9 grace the freeze wrote into the frozen set (and the
         * registry) = max(old, B + n_new x E) */
        const int mi = member_of(set->fps[i]);
        CHECK(mi >= 0, "a known member");
        uint64_t eg = g_grace[mi];
        if (want_nn > 0 && B + (uint64_t)want_nn * E_LEN > eg)
            eg = B + (uint64_t)want_nn * E_LEN;
        CHECK(set->grace_until[i] == eg,
              "G: grace_until = max(old, B + n_new x E) (K9)");
        g_grace[mi] = eg;
    }
    return 0;
}

/* one generation-6 boundary: publish `n_new_seg` segments, freeze, check.
 * `prev`/`is_b1`: the previous relation; fills `cur_out` for the next. */
static int boundary(nodus_witness_t *w, uint64_t B, size_t R,
                    unsigned n_new_seg, const rel_t *prev, int is_b1,
                    rel_t *cur_out, int expect_change, const char *label) {
    snprintf(g_ctx, sizeof(g_ctx), "%s", label);
    for (unsigned i = 0; i < n_new_seg; i++) {
        g_nseg++;
        g_pub[g_nseg] = B;
        CHECK(seg_put(w, g_nseg, B) == 0, "segment published");
    }
    nodus_storage_boundary_t out;
    memset(&out, 0, sizeof(out));
    out.n_published = n_new_seg;
    CHECK(sqlx(w, "BEGIN IMMEDIATE") == 0, "begin");
    const int rc = nodus_witness_storage_freeze_gen6(
                       w, B, (uint32_t)R, DNA_V2_STORAGE_SET_LIMIT_GEN6, &out);
    CHECK(rc == 0, "the generation-6 freeze applies");
    CHECK(sqlx(w, "COMMIT") == 0, "commit");
    nodus_storage_set_t *set = calloc(1, sizeof(*set));
    rel_t *cur = calloc(1, sizeof(*cur));
    CHECK(set && cur, "alloc");
    CHECK(nodus_witness_storage_set_get(w, B, set) == 0, "set(B) readable");
    CHECK(rel_hrw(set, R, cur) == 0, "model relation");
    if (expect_change)
        CHECK(rel_changed(prev, cur) > 0,
              "the case changes at least one holder (false-pass guard)");
    int r1 = check_rows_held_state(w, B, R, set, cur, is_b1);
    int r2 = r1 ? r1 : check_union(w, B, set, cur, prev);
    if (!r2) memcpy(cur_out, cur, sizeof(*cur));
    free(cur);
    free(set);
    return r2;
}

/* ── scenarios ───────────────────────────────────────────────────────── */

/* the gen-5 history: sets at 3E, 4E, 5E (= H2) and segments 1..10 */
static int plant_history(nodus_witness_t *w, int with_segments) {
    static const unsigned s3[] = { 0, 1, 2, 3, 4, 5, 6, 7 };
    static const unsigned s4[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
    static const unsigned s5[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    if (plant_set(w, 3 * E_LEN, s3, 8) != 0 ||
        plant_set(w, 4 * E_LEN, s4, 9) != 0 ||
        plant_set(w, 5 * E_LEN, s5, 10) != 0)
        return -1;
    for (unsigned i = 0; i < 10; i++)
        if (reg_put(w, i, 1, 0) != 0) return -1;
    g_nseg = 0;
    if (with_segments)
        for (unsigned k = 1; k <= 10; k++) {
            g_pub[k] = k <= 4 ? 3 * E_LEN : k <= 8 ? 4 * E_LEN : 5 * E_LEN;
            if (seg_put(w, k, g_pub[k]) != 0) return -1;
            g_nseg = k;
        }
    /* param 18 (the storage gate) from block 1; param 24 effective at A =
     * H2 + 2, so no boundary lies in [A, B1) and A - 1 = H2 + 1 is the
     * edge block */
    return cc_row(w, DNAC_CFG_RULESET_GEN_ROLES, 1, 1, 1) != 0 ||
           cc_row(w, DNAC_CFG_RULESET_GEN_TRIE, 1, 5 * E_LEN + 2, 2) != 0
               ? -1 : 0;
}

static int edge_step(nodus_witness_t *w) {
    CHECK(sqlx(w, "BEGIN IMMEDIATE") == 0, "begin");
    CHECK(nodus_witness_storage_gen6_transition(w, 5 * E_LEN + 1) == 0,
          "the edge's storage transition (E-s1..E-s3) applies");
    CHECK(sqlx(w, "COMMIT") == 0, "commit");
    return 0;
}

/* the XOR union count of m in epoch (H, H+E] straight from the two frozen
 * sets - the model of E-s1 (not the walk the production code uses) */
static int xor_union(nodus_witness_t *w, uint64_t H, const uint8_t fp[64],
                     long long *out) {
    nodus_storage_set_t *cur = calloc(1, sizeof(*cur));
    nodus_storage_set_t *prv = calloc(1, sizeof(*prv));
    rel_t *rc = calloc(1, sizeof(*rc)), *rp = calloc(1, sizeof(*rp));
    int ok = -1;
    if (cur && prv && rc && rp &&
        nodus_witness_storage_set_get(w, H, cur) == 0 &&
        rel_xor(cur, H, rc) == 0) {
        int has_prev = nodus_witness_storage_set_get(w, H - E_LEN, prv) == 0;
        if (!has_prev) prv->count = 0;
        if (rel_xor(prv, H - E_LEN, rp) == 0) {
            long long n = 0;
            for (unsigned k = 1; k <= g_nseg; k++)
                if (in_rel(rc, k, fp) ||
                    (has_prev && g_pub[k] + E_LEN <= H && in_rel(rp, k, fp)))
                    n++;
            *out = n;
            ok = 0;
        }
    }
    free(rp); free(rc); free(prv); free(cur);
    return ok;
}

static int t_main_chain(void) {
    fx_t fx;
    CHECK(fx_open(&fx) == 0, "fixture");
    nodus_witness_t *w = fx.w;
    snprintf(g_ctx, sizeof(g_ctx), "main chain: edge");
    CHECK(plant_history(w, 1) == 0, "history");
    CHECK(edge_step(w) == 0, "edge");

    /* E-s1: the XOR union counts of the epochs settled at B1 and B1 + E */
    {
        nodus_storage_set_t *s = calloc(1, sizeof(*s));
        CHECK(s != NULL, "alloc");
        for (int which = 0; which < 2; which++) {
            const uint64_t H = which == 0 ? 4 * E_LEN : 5 * E_LEN;
            CHECK(nodus_witness_storage_set_get(w, H, s) == 0, "set");
            for (uint32_t i = 0; i < s->count; i++) {
                long long hu = 0, nn = 0, want = 0;
                CHECK(xor_union(w, H, s->fps[i], &want) == 0, "model");
                CHECK(me_row(w, H, s->fps[i], &hu, &nn) == 1 &&
                      hu == want && nn == 0,
                      "E-s1: member_epoch = the XOR union count, n_new 0");
            }
        }
        free(s);
    }
    /* E-s2: rows = holders_hrw over eligible(set(H2)), R = 4 */
    rel_t *prev = calloc(1, sizeof(*prev)), *cur = calloc(1, sizeof(*cur));
    rel_t *xr = calloc(1, sizeof(*xr));
    nodus_storage_set_t *h2 = calloc(1, sizeof(*h2));
    CHECK(prev && cur && xr && h2, "alloc");
    CHECK(nodus_witness_storage_set_get(w, 5 * E_LEN, h2) == 0, "set(H2)");
    CHECK(rel_hrw(h2, 4, cur) == 0 && rel_xor(h2, 5 * E_LEN, xr) == 0,
          "models");
    for (unsigned k = 1; k <= g_nseg; k++) {
        uint8_t rows[RMAX][64];
        size_t nr = 0;
        CHECK(cur_rows(w, k, rows, &nr) == 0 && nr == cur->n[k], "E-s2 rows");
        for (size_t i = 0; i < nr; i++)
            CHECK(memcmp(rows[i], cur->fp[k][i], 64) == 0,
                  "E-s2: rows = holders_hrw(set(H2)), R = 4");
    }
    CHECK(q1(w, "SELECT xfer FROM v2_storage_assign_state") == 1 &&
          q1(w, "SELECT boundary FROM v2_storage_assign_state") ==
              (long long)(5 * E_LEN) &&
          q1(w, "SELECT copies FROM v2_storage_assign_state") == 4,
          "E-s2: state (4, H2, xfer 1)");
    CHECK(rel_changed(xr, cur) > 0 &&
          q1(w, "SELECT COUNT(*) FROM v2_storage_xfer_diff") > 0,
          "E-s3: XOR and rendezvous differ and the one-use table has rows");
    memcpy(prev, xr, sizeof(*prev));           /* prev relation at B1 = XOR */

    /* B1: no event (eligible and R unchanged), a new segment published */
    uint64_t B = 6 * E_LEN;
    CHECK(boundary(w, B, 4, 1, prev, 1, cur, 1,
                   "B1 without an event (xfer table)") == 0, "B1");
    memcpy(prev, cur, sizeof(*prev));

    /* ordinary: a new segment only */
    B += E_LEN;
    CHECK(boundary(w, B, 4, 1, prev, 0, cur, 0, "ordinary + new segment")
          == 0, "ordinary");
    memcpy(prev, cur, sizeof(*prev));

    /* one arrival: join */
    CHECK(reg_put(w, 10, 1, 0) == 0, "M10 registers");
    B += E_LEN;
    CHECK(boundary(w, B, 4, 0, prev, 0, cur, 1, "one arrival (join rule)")
          == 0, "join");
    memcpy(prev, cur, sizeof(*prev));

    /* two arrivals, both entering some top R: assert the case from the
     * model BEFORE the engine runs */
    CHECK(reg_put(w, 11, 1, 0) == 0 && reg_put(w, 12, 1, 0) == 0,
          "M11, M12 register");
    {
        nodus_storage_set_t *s = calloc(1, sizeof(*s));
        rel_t *m = calloc(1, sizeof(*m));
        CHECK(s && m, "alloc");
        /* the set that WILL be frozen: the ACTIVE rows now */
        uint8_t all[NMEM][64];
        unsigned na = 0;
        for (unsigned i = 0; i < NMEM; i++) {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(w->db, "SELECT status FROM "
                    "v2_storage_nodes WHERE node_fp = ?1", -1, &st, NULL)
                  == SQLITE_OK, "status query");
            sqlite3_bind_blob(st, 1, g_fp[i], 64, SQLITE_STATIC);
            if (sqlite3_step(st) == SQLITE_ROW &&
                sqlite3_column_int(st, 0) == 1)
                memcpy(all[na++], g_fp[i], 64);
            sqlite3_finalize(st);
        }
        sort_fps(all, na);
        for (unsigned i = 0; i < na; i++) {
            memcpy(s->fps[i], all[i], 64);
            s->fail_streak[i] = 0;
        }
        s->count = na;
        CHECK(rel_hrw(s, 4, m) == 0, "model");
        /* the discriminating condition for a join rule that compares each
         * arrival against the STALE R-th score: both arrivals rank above
         * the old R-th (4th) best of some segment, so each is admitted
         * against it while only ONE position is open (the old R-th) - the
         * stale rule would then hold R + 1 members. Known to hold for this
         * fixture (hashlib.sha3_512 re-derivation, see the header). */
        int beat = 0;
        for (unsigned k = 1; k <= g_nseg; k++) {
            uint8_t root[64], a[64], s4[64], sa[64], sb[64];
            seg_root(k, root);
            CHECK(dna_v2_segment_assign_key(root, a) == 0 &&
                  prev->n[k] == 4, "old holders");
            int first = 1;
            for (size_t i = 0; i < prev->n[k]; i++) {
                uint8_t sc[64];
                CHECK(dna_v2_segment_score(a, prev->fp[k][i], sc) == 0,
                      "score");
                if (first || memcmp(sc, s4, 64) < 0) {
                    memcpy(s4, sc, 64);
                    first = 0;
                }
            }
            CHECK(dna_v2_segment_score(a, g_fp[11], sa) == 0 &&
                  dna_v2_segment_score(a, g_fp[12], sb) == 0, "scores");
            if (memcmp(sa, s4, 64) > 0 && memcmp(sb, s4, 64) > 0) beat++;
        }
        CHECK(beat > 0,
              "the two-arrivals case: at least one segment where BOTH "
              "arrivals beat the old 4th-best score (guard of the "
              "join-rule case)");
        free(m);
        free(s);
    }
    B += E_LEN;
    CHECK(boundary(w, B, 4, 0, prev, 0, cur, 1,
                   "two arrivals (join rule, one slot each)") == 0, "two");
    memcpy(prev, cur, sizeof(*prev));

    /* a departure: M3 exits (not ACTIVE), a new segment too */
    CHECK(reg_put(w, 3, 2, 0) == 0, "M3 EXITING");
    B += E_LEN;
    CHECK(boundary(w, B, 4, 1, prev, 0, cur, 1, "departure of a holder")
          == 0, "departure");
    memcpy(prev, cur, sizeof(*prev));

    /* fail_streak crossing up (M5 -> 3) and back down */
    CHECK(reg_put(w, 5, 1, 3) == 0, "M5 fail_streak 3");
    B += E_LEN;
    CHECK(boundary(w, B, 4, 0, prev, 0, cur, 1,
                   "eligibility crossing up (fail_streak 3)") == 0, "up");
    memcpy(prev, cur, sizeof(*prev));
    CHECK(reg_put(w, 5, 1, 0) == 0, "M5 fail_streak 0");
    B += E_LEN;
    CHECK(boundary(w, B, 4, 0, prev, 0, cur, 1,
                   "eligibility crossing back down") == 0, "down");
    memcpy(prev, cur, sizeof(*prev));

    /* R 4 -> 6 -> 4 through param 25 rows */
    B += E_LEN;
    CHECK(cc_row(w, DNAC_CFG_STORAGE_COPIES, 6, B, 3) == 0, "param 25 = 6");
    {
        uint32_t r = 0;
        CHECK(nodus_witness_storage_copies_at(w, B, &r) == 0 && r == 6 &&
              nodus_witness_storage_copies_at(w, B - 1, &r) == 0 && r == 4,
              "param 25 reader: 6 from its effective block, 4 before");
    }
    CHECK(boundary(w, B, 6, 0, prev, 0, cur, 1, "R 4 -> 6 (event)") == 0,
          "r up");
    memcpy(prev, cur, sizeof(*prev));
    B += E_LEN;
    CHECK(cc_row(w, DNAC_CFG_STORAGE_COPIES, 4, B, 4) == 0, "param 25 = 4");
    CHECK(boundary(w, B, 4, 1, prev, 0, cur, 1, "R 6 -> 4 (event)") == 0,
          "r down");
    memcpy(prev, cur, sizeof(*prev));

    /* R = 16 through the retained maintenance (Sol row 10; plan T-7 "R 16"):
     * M3 returns and M13..M17 register, so 18 members are eligible; first
     * an arrivals boundary at R = 4, then R 4 -> 16 (param 25 = 16): each
     * segment holds exactly 16 of the 18, the counts follow the relation */
    CHECK(reg_put(w, 3, 1, 0) == 0, "M3 returns");
    for (unsigned i = 13; i <= 17; i++)
        CHECK(reg_put(w, i, 1, 0) == 0, "M13..M17 register");
    B += E_LEN;
    CHECK(boundary(w, B, 4, 0, prev, 0, cur, 1, "six arrivals at R = 4")
          == 0, "arrivals");
    memcpy(prev, cur, sizeof(*prev));
    B += E_LEN;
    CHECK(cc_row(w, DNAC_CFG_STORAGE_COPIES, 16, B, 6) == 0,
          "param 25 = 16");
    CHECK(boundary(w, B, 16, 1, prev, 0, cur, 1, "R 4 -> 16 (event)") == 0,
          "r 16");
    for (unsigned k = 1; k <= g_nseg; k++)
        CHECK(cur->n[k] == 16, "R = 16: exactly 16 of the 18 eligible");
    memcpy(prev, cur, sizeof(*prev));
    B += E_LEN;
    CHECK(cc_row(w, DNAC_CFG_STORAGE_COPIES, 4, B, 7) == 0, "param 25 = 4");
    CHECK(boundary(w, B, 4, 0, prev, 0, cur, 1, "R 16 -> 4 (event)") == 0,
          "r 16 down");

    /* PRUNE through the real step 2 (Sol round 3 row 6): member_epoch is
     * pruned with the set members - rows of epochs below B - 2E go, the
     * rest stay */
    snprintf(g_ctx, sizeof(g_ctx), "prune");
    {
        char sql[200];
        const long long H = (long long)(B - 2 * E_LEN);
        snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM "
                 "v2_storage_member_epoch WHERE epoch_start < %lld", H);
        CHECK(q1(w, sql) > 0, "expired member_epoch rows exist before the "
                              "prune (the case has something to remove)");
        snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM "
                 "v2_storage_set_members WHERE epoch_start < %lld", H);
        CHECK(q1(w, sql) > 0, "expired set member rows exist before");
        CHECK(sqlx(w, "BEGIN IMMEDIATE") == 0 &&
              nodus_witness_storage_prune(w, B, 1) == 0 &&
              sqlx(w, "COMMIT") == 0, "the prune step runs");
        snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM "
                 "v2_storage_member_epoch WHERE epoch_start < %lld", H);
        CHECK(q1(w, sql) == 0, "member_epoch below B - 2E is pruned");
        snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM "
                 "v2_storage_set_members WHERE epoch_start < %lld", H);
        CHECK(q1(w, sql) == 0, "set members below B - 2E are pruned (the "
                               "same rule)");
        snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM "
                 "v2_storage_member_epoch WHERE epoch_start >= %lld", H);
        CHECK(q1(w, sql) > 0, "member_epoch from B - 2E on survives");
        snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM "
                 "v2_storage_assign WHERE to_h IS NOT NULL");
        CHECK(q1(w, sql) > 0, "ended assignment rows are never pruned (D6)");
    }

    /* the state guards: a skipped boundary is stale derived data */
    snprintf(g_ctx, sizeof(g_ctx), "state guards");
    {
        nodus_storage_boundary_t o;
        memset(&o, 0, sizeof(o));
        CHECK(sqlx(w, "BEGIN IMMEDIATE") == 0, "begin");
        CHECK(nodus_witness_storage_freeze_gen6(w, B + 3 * E_LEN, 4,
                  DNA_V2_STORAGE_SET_LIMIT_GEN6, &o) == -2,
              "a boundary that skips one: the state is stale - FAULT");
        CHECK(sqlx(w, "ROLLBACK") == 0, "rollback");
        CHECK(sqlx(w, "BEGIN IMMEDIATE") == 0, "begin");
        CHECK(nodus_witness_storage_freeze_gen6(w, B + E_LEN, 4, 3, &o) == -2,
              "a member cap below the ACTIVE count: FAULT");
        CHECK(sqlx(w, "ROLLBACK") == 0, "rollback");
        CHECK(sqlx(w, "BEGIN IMMEDIATE") == 0, "begin");
        CHECK(sqlx(w, "DELETE FROM v2_storage_assign_state") == 0, "drop");
        CHECK(nodus_witness_storage_freeze_gen6(w, B + E_LEN, 4,
                  DNA_V2_STORAGE_SET_LIMIT_GEN6, &o) == -2,
              "no state although set(B - E) exists: FAULT");
        CHECK(sqlx(w, "ROLLBACK") == 0, "rollback");
    }
    /* param 25 outside [4, 16] is corrupt chain_config */
    {
        uint32_t r = 0;
        CHECK(cc_row(w, DNAC_CFG_STORAGE_COPIES, 17, B + 100 * E_LEN, 5) == 0,
              "a corrupt row");
        CHECK(nodus_witness_storage_copies_at(w, B + 100 * E_LEN, &r) == -1,
              "a stored 17 is refused, never read as a value");
    }
    free(h2); free(xr); free(cur); free(prev);
    fx_close(&fx);
    return 0;
}

/* B1 with an event: M0 leaves and M10 arrives between H2 and B1 */
static int t_b1_event(void) {
    fx_t fx;
    CHECK(fx_open(&fx) == 0, "fixture");
    nodus_witness_t *w = fx.w;
    snprintf(g_ctx, sizeof(g_ctx), "B1 event: edge");
    CHECK(plant_history(w, 1) == 0 && edge_step(w) == 0, "edge");
    rel_t *prev = calloc(1, sizeof(*prev)), *cur = calloc(1, sizeof(*cur));
    nodus_storage_set_t *h2 = calloc(1, sizeof(*h2));
    CHECK(prev && cur && h2, "alloc");
    CHECK(nodus_witness_storage_set_get(w, 5 * E_LEN, h2) == 0 &&
          rel_xor(h2, 5 * E_LEN, prev) == 0, "XOR(set(H2))");
    CHECK(reg_put(w, 0, 2, 0) == 0 && reg_put(w, 10, 1, 0) == 0,
          "M0 leaves, M10 joins");
    const uint64_t B = 6 * E_LEN;
    snprintf(g_ctx, sizeof(g_ctx), "B1 with an event");
    g_nseg++;
    g_pub[g_nseg] = B;
    CHECK(seg_put(w, g_nseg, B) == 0, "segment published at B1");
    nodus_storage_boundary_t out;
    memset(&out, 0, sizeof(out));
    out.n_published = 1;
    CHECK(sqlx(w, "BEGIN IMMEDIATE") == 0, "begin");
    CHECK(nodus_witness_storage_freeze_gen6(w, B, 4,
              DNA_V2_STORAGE_SET_LIMIT_GEN6, &out) == 0, "freeze");
    CHECK(sqlx(w, "COMMIT") == 0, "commit");
    nodus_storage_set_t *set = calloc(1, sizeof(*set));
    CHECK(set && nodus_witness_storage_set_get(w, B, set) == 0 &&
          rel_hrw(set, 4, cur) == 0, "model");
    CHECK(rel_changed(prev, cur) > 0, "the event changes holders");
    /* group 1: ROW correctness (rows ended / inserted against the E-s2
     * rows, final rows = the rendezvous holders over eligible(B1)) */
    CHECK(check_rows_held_state(w, B, 4, set, cur, 1) == 0,
          "B1 event: row correctness");
    /* group 2: COUNTING correctness (ended / n_new against XOR(set(H2)),
     * publication cutoff, members of set(B1) only) - a separate group */
    CHECK(check_union(w, B, set, cur, prev) == 0,
          "B1 event: counting correctness");
    free(set); free(h2); free(cur); free(prev);
    fx_close(&fx);
    return 0;
}

/* no set(H2): the gate opened in the last gen-5 epoch */
static int t_no_set_h2(void) {
    fx_t fx;
    CHECK(fx_open(&fx) == 0, "fixture");
    nodus_witness_t *w = fx.w;
    snprintf(g_ctx, sizeof(g_ctx), "no set(H2)");
    for (unsigned i = 0; i < 6; i++) CHECK(reg_put(w, i, 1, 0) == 0, "reg");
    g_nseg = 0;
    CHECK(cc_row(w, DNAC_CFG_RULESET_GEN_ROLES, 1, 1, 1) == 0 &&
          cc_row(w, DNAC_CFG_RULESET_GEN_TRIE, 1, 5 * E_LEN + 2, 2) == 0,
          "params");
    CHECK(edge_step(w) == 0, "edge with no set and no segment");
    CHECK(q1(w, "SELECT xfer FROM v2_storage_assign_state") == 0 &&
          q1(w, "SELECT COUNT(*) FROM v2_storage_assign_basis") == 0,
          "xfer 0 (no XOR history), empty basis");
    rel_t *prev = calloc(1, sizeof(*prev)), *cur = calloc(1, sizeof(*cur));
    CHECK(prev && cur, "alloc");
    CHECK(boundary(w, 6 * E_LEN, 4, 1, prev, 1, cur, 1,
                   "B1 as a first freeze (event path, empty basis)") == 0,
          "first freeze");
    free(cur); free(prev);
    fx_close(&fx);
    return 0;
}

/* The one-use table's absence is accepted ONLY when the state row says
 * xfer = 0 (consumed / never pending): three negative cases and the
 * accepted one (Sol round 3 row 2; the refusal rule of
 * s20_storage_shape_ok). */
static int t_xfer_absence(void) {
    fx_t fx;
    CHECK(fx_open(&fx) == 0, "fixture");
    nodus_witness_t *w = fx.w;
    snprintf(g_ctx, sizeof(g_ctx), "xfer absence");
    /* no state row at all (before the edge): the table is required */
    CHECK(sqlx(w, "DROP TABLE v2_storage_xfer_diff") == 0, "drop (no state)");
    CHECK(nodus_witness_db_s20_reseed(w) == -1,
          "absent table, NO state row: refused");
    fx_close(&fx);

    CHECK(fx_open(&fx) == 0, "fixture 2");
    w = fx.w;
    CHECK(plant_history(w, 1) == 0 && edge_step(w) == 0, "edge");
    CHECK(q1(w, "SELECT xfer FROM v2_storage_assign_state") == 1,
          "the transfer is pending");
    CHECK(nodus_witness_db_s20_reseed(w) == 0, "table present, pending: ok");
    CHECK(sqlx(w, "DROP TABLE v2_storage_xfer_diff") == 0, "drop (pending)");
    CHECK(nodus_witness_db_s20_reseed(w) == -1,
          "absent table, transfer PENDING (xfer = 1): refused");
    CHECK(sqlx(w, "UPDATE v2_storage_assign_state SET xfer = 0") == 0,
          "consume");
    CHECK(nodus_witness_db_s20_reseed(w) == 0,
          "absent table, xfer = 0: accepted");
    fx_close(&fx);
    return 0;
}

/* fewer eligible members than R, and an empty set */
static int t_fewer_than_r(void) {
    fx_t fx;
    CHECK(fx_open(&fx) == 0, "fixture");
    nodus_witness_t *w = fx.w;
    snprintf(g_ctx, sizeof(g_ctx), "fewer than R");
    for (unsigned i = 0; i < 3; i++) CHECK(reg_put(w, i, 1, 0) == 0, "reg");
    g_nseg = 0;
    CHECK(cc_row(w, DNAC_CFG_RULESET_GEN_ROLES, 1, 1, 1) == 0 &&
          cc_row(w, DNAC_CFG_RULESET_GEN_TRIE, 1, 5 * E_LEN + 2, 2) == 0 &&
          edge_step(w) == 0, "edge");
    rel_t *prev = calloc(1, sizeof(*prev)), *cur = calloc(1, sizeof(*cur));
    CHECK(prev && cur, "alloc");
    CHECK(boundary(w, 6 * E_LEN, 4, 2, prev, 1, cur, 1,
                   "3 eligible, R 4: all hold") == 0, "all hold");
    for (unsigned k = 1; k <= g_nseg; k++)
        CHECK(cur->n[k] == 3, "every segment has exactly 3 holders (< R)");
    memcpy(prev, cur, sizeof(*prev));
    CHECK(reg_put(w, 3, 1, 0) == 0, "a fourth member");
    CHECK(boundary(w, 7 * E_LEN, 4, 0, prev, 0, cur, 1,
                   "an arrival fills an open position") == 0, "fills");
    for (unsigned k = 1; k <= g_nseg; k++)
        CHECK(cur->n[k] == 4, "now R holders");
    free(cur); free(prev);
    fx_close(&fx);
    return 0;
}

/* the generation-6 cap: 1024 members against a 2-copy model, and a cap
 * given to the freeze that is one below the ACTIVE count */
static int t_cap_1024(void) {
    fx_t fx;
    CHECK(fx_open(&fx) == 0, "fixture");
    nodus_witness_t *w = fx.w;
    snprintf(g_ctx, sizeof(g_ctx), "cap 1024");
    CHECK(cc_row(w, DNAC_CFG_RULESET_GEN_ROLES, 1, 1, 1) == 0 &&
          cc_row(w, DNAC_CFG_RULESET_GEN_TRIE, 1, 5 * E_LEN + 2, 2) == 0 &&
          edge_step(w) == 0, "edge");
    /* 1024 ACTIVE rows (the registry loader requires fp = SHA3-512(pk)) */
    static uint8_t pk[DNAC_PUBKEY_SIZE];
    CHECK(sqlx(w, "BEGIN") == 0, "begin");
    for (unsigned i = 0; i < DNA_V2_STORAGE_SET_LIMIT_GEN6; i++) {
        uint8_t fp[64];
        memset(pk, 0, sizeof(pk));
        pk[0] = (uint8_t)(i >> 8);
        pk[1] = (uint8_t)i;
        pk[2] = 0x5C;
        CHECK(qgp_sha3_512(pk, sizeof(pk), fp) == 0, "fp");
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(w->db,
              "INSERT INTO v2_storage_nodes (node_fp, node_pk, payee_fp, "
              "bond, status, registered_height, exit_height, fail_streak, "
              "grace_until) VALUES (?1, ?2, zeroblob(64), 1000, 1, 1, 0, 0, "
              "0)", -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, fp, 64, SQLITE_STATIC);
        sqlite3_bind_blob(st, 2, pk, sizeof(pk), SQLITE_STATIC);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "insert");
        sqlite3_finalize(st);
    }
    CHECK(sqlx(w, "COMMIT") == 0, "commit");
    CHECK(seg_put(w, 1, 6 * E_LEN) == 0, "segment 1");
    nodus_storage_boundary_t out;
    memset(&out, 0, sizeof(out));
    out.n_published = 1;
    CHECK(sqlx(w, "BEGIN IMMEDIATE") == 0, "begin");
    CHECK(nodus_witness_storage_freeze_gen6(w, 6 * E_LEN, 4,
              DNA_V2_STORAGE_SET_LIMIT_GEN6 - 1, &out) == -2,
          "1024 ACTIVE rows with a 1023 limit: FAULT");
    CHECK(sqlx(w, "ROLLBACK") == 0, "rollback");
    CHECK(sqlx(w, "BEGIN IMMEDIATE") == 0, "begin");
    memset(&out, 0, sizeof(out));
    out.n_published = 1;
    CHECK(nodus_witness_storage_freeze_gen6(w, 6 * E_LEN, 4,
              DNA_V2_STORAGE_SET_LIMIT_GEN6, &out) == 0 &&
          out.set_count == 1024, "1024 members freeze");
    CHECK(sqlx(w, "COMMIT") == 0, "commit");
    {
        nodus_storage_set_t *set = calloc(1, sizeof(*set));
        CHECK(set && nodus_witness_storage_set_get(w, 6 * E_LEN, set) == 0 &&
              set->count == 1024, "set(B1) with 1024 members re-derives");
        uint8_t root[64], a[64];
        size_t idx[RMAX], nh = 0;
        seg_root(1, root);
        CHECK(dna_v2_segment_assign_key(root, a) == 0 &&
              dna_v2_segment_holders_hrw(a, (const uint8_t (*)[64])set->fps,
                                         set->fail_streak, set->count, 4,
                                         idx, &nh) == 0 && nh == 4,
              "model");
        uint8_t rows[RMAX][64];
        size_t nr = 0;
        CHECK(cur_rows(w, 1, rows, &nr) == 0 && nr == 4, "4 rows");
        for (size_t i = 0; i < nr; i++) {
            int found = 0;
            for (size_t j = 0; j < nh; j++)
                if (memcmp(rows[i], set->fps[idx[j]], 64) == 0) found = 1;
            CHECK(found, "the 1024-member rows = holders_hrw");
        }
        free(set);
    }
    fx_close(&fx);
    return 0;
}

int main(void) {
    if (members_init() != 0) return 1;
    if (t_main_chain() != 0) return 1;
    if (t_b1_event() != 0) return 1;
    if (t_no_set_h2() != 0) return 1;
    if (t_xfer_absence() != 0) return 1;
    if (t_fewer_than_r() != 0) return 1;
    if (t_cap_1024() != 0) return 1;
    printf("test_storage_hrw: ALL %d checks passed\n", g_checks);
    return 0;
}
