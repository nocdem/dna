/**
 * @file nodus/tests/test_storage_hrw_runtime.c
 * @brief HF-9 WP4, plan row T-16 - the ACTUAL probe and holder paths over
 *        the generation-6 assignment: nodus_witness_storage_eligible_
 *        segments (the probe's eligible list, also the probed node's
 *        answer), nodus_witness_sthold_must_hold (the holder runtime's
 *        must-hold list) and nodus_witness_storage_holders_at (the fetch
 *        client's candidate holders) against the full current / previous
 *        relation, for every member and epoch of a scratch S20 chain.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  After the edge step and each of four generation-6 boundaries (B1, a
 *  join, a departure with an eligibility crossing, a replica-count change
 *  4 -> 6), for EVERY member fixture (members of set(B) and not):
 *   M  must_hold(B, m) = {k : m in cur(k)} U {k published <= B - E :
 *      m in prev(k)}, ascending, no grace gate;
 *   P  eligible_segments(B, m) = the same list for a member of set(B)
 *      that is not in grace at B, empty for a member in grace and for a
 *      non-member;
 *   C  holders_at(k, root, B) = cur(k) and holders_at(k, root, B - E) =
 *      prev(k) (the assignment rows from generation 6, XOR over the frozen
 *      set below - the B1 transition epoch H2);
 *  where cur(k) = holders_hrw over set(B) with R(B) and prev(k) is the
 *  previous boundary's relation, at B1 XOR(set(H2)) over the segments
 *  published at or before H2 (the model is computed from the selector
 *  functions, not from the assignment tables). Every case is asserted to
 *  change at least one member's must-hold list (the plan's false-pass
 *  guard). The epoch H2 (generation <= 5) is checked through the same
 *  functions against the XOR relation: the historical path is unchanged.
 *  The same cases on the 7-node harness (the holder runtime fetching the
 *  newly assigned segments and dropping others only after the overlap
 *  epoch, probe reports carrying bits for the new holders) are T-13's.
 *
 * ── FLAGS ───────────────────────────────────────────────────────────────
 *  register_witness_test (NODUS_WITNESS_INTERNAL_API), only where the
 *  EVM runtime is. The plan's short-epoch flag is not required: segments
 *  and sets are seeded, boundaries are multiples of DNAC_EPOCH_LENGTH.
 *  Leaves /tmp/test_storage_hrw_runtime_XXXXXX (removed at exit).
 *
 * ── HOW IT CAN FALSELY PASS OR SKIP ─────────────────────────────────────
 *  The model shares the selector function with production (pinned to the
 *  independent oracle by test_hf9_kat). The grace case relies on a
 *  member whose K9 grace the freeze actually set (asserted: at least one
 *  member is in grace at some checked boundary, else the case fails).
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_storage_holder.h"
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

#define E_LEN  ((uint64_t)DNAC_EPOCH_LENGTH)
#define NMEM   16u
#define NSEG   24u
#define RMAX   DNA_V2_STORAGE_HOLDERS_CAP

static nodus_witness_t *g_w;
static char g_dir[128];
static uint8_t g_pk[NMEM][DNAC_PUBKEY_SIZE];
static uint8_t g_fp[NMEM][64];
static uint64_t g_pub[NSEG + 1];
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

static int reg_put(unsigned i, int status, unsigned fs) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_w->db,
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
    if (sqlite3_changes(g_w->db) == 1) return 0;
    st = NULL;
    if (sqlite3_prepare_v2(g_w->db,
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

static int seg_put(unsigned k, uint64_t pub) {
    uint8_t r[64];
    seg_root(k, r);
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
    g_pub[k] = pub;
    g_nseg = k;
    return rc == SQLITE_DONE ? 0 : -1;
}

static void sort_fps(uint8_t (*l)[64], size_t n) {
    for (size_t i = 1; i < n; i++)
        for (size_t j = i; j > 0 && memcmp(l[j - 1], l[j], 64) > 0; j--) {
            uint8_t t[64];
            memcpy(t, l[j], 64);
            memcpy(l[j], l[j - 1], 64);
            memcpy(l[j - 1], t, 64);
        }
}

static int plant_set(uint64_t H, unsigned count) {
    uint8_t fps[NMEM][64];
    for (unsigned i = 0; i < count; i++) memcpy(fps[i], g_fp[i], 64);
    sort_fps(fps, count);
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

/* ── the model ───────────────────────────────────────────────────────── */

typedef struct {
    size_t  n[NSEG + 1];
    uint8_t fp[NSEG + 1][RMAX][64];
} rel_t;

static int in_rel(const rel_t *r, unsigned k, const uint8_t fp[64]) {
    for (size_t i = 0; i < r->n[k]; i++)
        if (memcmp(r->fp[k][i], fp, 64) == 0) return 1;
    return 0;
}

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
        for (size_t i = 0; i < nh; i++)
            memcpy(out->fp[k][i], set->fps[idx[i]], 64);
    }
    return 0;
}

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
    }
    return 0;
}

/* the expected ascending list for member m at boundary B */
static size_t expect_ks(const rel_t *cur, const rel_t *prev, uint64_t B,
                        const uint8_t fp[64], uint64_t *ks) {
    size_t n = 0;
    for (unsigned k = 1; k <= g_nseg; k++)
        if (in_rel(cur, k, fp) ||
            (g_pub[k] + E_LEN <= B && in_rel(prev, k, fp)))
            ks[n++] = k;
    return n;
}

static int same_list(const uint64_t *a, size_t na, const uint64_t *b,
                     size_t nb) {
    if (na != nb) return 0;
    for (size_t i = 0; i < na; i++)
        if (a[i] != b[i]) return 0;
    return 1;
}

/* all three probe / holder paths for every member at B */
static int check_paths(uint64_t B, const rel_t *cur, const rel_t *prev,
                       const nodus_storage_set_t *set, int *in_grace_seen,
                       uint64_t last_lists[NMEM][NSEG + 1],
                       size_t last_n[NMEM], int *changed_any) {
    for (unsigned m = 0; m < NMEM; m++) {
        uint64_t want[NSEG + 1], got[NSEG + 1];
        size_t nw = expect_ks(cur, prev, B, g_fp[m], want), ng = 0;
        CHECK(nodus_witness_sthold_must_hold(g_w, B, g_fp[m], got, NSEG + 1,
                                             &ng) == 0,
              "must_hold runs");
        CHECK(same_list(want, nw, got, ng),
              "M: must-hold = cur U (prev for k published <= B - E)");
        /* P: the probe's eligible list */
        long mi = -1;
        for (uint32_t i = 0; i < set->count; i++)
            if (memcmp(set->fps[i], g_fp[m], 64) == 0) mi = (long)i;
        size_t ne = 99;
        uint64_t eg[NSEG + 1];
        CHECK(nodus_witness_storage_eligible_segments(g_w, B, g_fp[m], eg,
                                                      NSEG + 1, &ne) == 0,
              "eligible_segments runs");
        if (mi < 0 || nodus_storage_in_grace(B, set->grace_until[mi])) {
            CHECK(ne == 0, "P: a non-member / a member in grace has none");
            if (mi >= 0) *in_grace_seen = 1;
        } else {
            CHECK(same_list(want, nw, eg, ne),
                  "P: eligible = the same list for a member out of grace");
        }
        if (!same_list(last_lists[m], last_n[m], got, ng)) *changed_any = 1;
        memcpy(last_lists[m], got, ng * sizeof(got[0]));
        last_n[m] = ng;
    }
    /* C: holders_at at B and at B - E for every segment */
    for (unsigned k = 1; k <= g_nseg; k++) {
        uint8_t root[64], hf[RMAX][64];
        size_t nh = 0;
        seg_root(k, root);
        CHECK(nodus_witness_storage_holders_at(g_w, k, root, B, hf, &nh) == 0
              && nh == cur->n[k], "C: holders_at(B) count");
        for (size_t i = 0; i < nh; i++)
            CHECK(in_rel(cur, k, hf[i]), "C: holders_at(B) = cur(k)");
        if (g_pub[k] + E_LEN <= B) {
            CHECK(nodus_witness_storage_holders_at(g_w, k, root, B - E_LEN,
                                                   hf, &nh) == 0 &&
                  nh == prev->n[k], "C: holders_at(B - E) count");
            for (size_t i = 0; i < nh; i++)
                CHECK(in_rel(prev, k, hf[i]), "C: holders_at(B - E) = prev(k)");
        }
    }
    return 0;
}

static int freeze(uint64_t B, size_t R, unsigned n_new_seg) {
    for (unsigned i = 0; i < n_new_seg; i++)
        if (seg_put(g_nseg + 1, B) != 0) return -1;
    nodus_storage_boundary_t out;
    memset(&out, 0, sizeof(out));
    out.n_published = n_new_seg;
    if (sqlx("BEGIN IMMEDIATE") != 0) return -1;
    int rc = nodus_witness_storage_freeze_gen6(
                 g_w, B, (uint32_t)R, DNA_V2_STORAGE_SET_LIMIT_GEN6, &out);
    if (rc != 0) { (void)sqlx("ROLLBACK"); return -1; }
    return sqlx("COMMIT");
}

int main(void) {
    for (unsigned i = 0; i < NMEM; i++) {
        for (size_t j = 0; j < DNAC_PUBKEY_SIZE; j++)
            g_pk[i][j] = (uint8_t)(i * 37u + j * 11u + 5u);
        g_pk[i][0] = (uint8_t)i;
        g_pk[i][1] = 0xA7;
        if (qgp_sha3_512(g_pk[i], DNAC_PUBKEY_SIZE, g_fp[i]) != 0) return 1;
    }
    g_w = calloc(1, sizeof(*g_w));
    CHECK(g_w != NULL, "alloc");
    snprintf(g_dir, sizeof(g_dir), "/tmp/test_storage_hrw_runtime_XXXXXX");
    CHECK(mkdtemp(g_dir) != NULL, "tmpdir");
    snprintf(g_w->data_path, sizeof(g_w->data_path), "%s", g_dir);
    uint8_t c16[16];
    memset(c16, 0x45, sizeof(c16));
    CHECK(nodus_witness_create_chain_db(g_w, c16) == 0 &&
          nodus_witness_db_migrate_v2s20(g_w) == 0, "fixture");

    /* the generation-5 history: sets 3E, 4E, 5E (= H2); segments 1..10 */
    CHECK(plant_set(3 * E_LEN, 8) == 0 && plant_set(4 * E_LEN, 9) == 0 &&
          plant_set(5 * E_LEN, 10) == 0, "sets");
    for (unsigned i = 0; i < 10; i++) CHECK(reg_put(i, 1, 0) == 0, "reg");
    for (unsigned k = 1; k <= 10; k++)
        CHECK(seg_put(k, k <= 4 ? 3 * E_LEN : k <= 8 ? 4 * E_LEN
                                                     : 5 * E_LEN) == 0,
              "segments");
    CHECK(cc_row(DNAC_CFG_RULESET_GEN_ROLES, 1, 1, 1) == 0 &&
          cc_row(DNAC_CFG_RULESET_GEN_TRIE, 1, 5 * E_LEN + 2, 2) == 0,
          "params");
    CHECK(sqlx("BEGIN IMMEDIATE") == 0 &&
          nodus_witness_storage_gen6_transition(g_w, 5 * E_LEN + 1) == 0 &&
          sqlx("COMMIT") == 0, "the edge's storage transition");

    rel_t *prev = calloc(1, sizeof(*prev)), *cur = calloc(1, sizeof(*cur));
    nodus_storage_set_t *set = calloc(1, sizeof(*set));
    static uint64_t last[NMEM][NSEG + 1];
    size_t last_n[NMEM];
    memset(last_n, 0, sizeof(last_n));
    CHECK(prev && cur && set, "alloc");
    int grace_seen = 0, changed = 0;

    /* H2 (generation <= 5): the same functions answer from the XOR
     * relation, unchanged */
    snprintf(g_ctx, sizeof(g_ctx), "H2 (historical path)");
    {
        nodus_storage_set_t *s4 = calloc(1, sizeof(*s4));
        rel_t *x5 = calloc(1, sizeof(*x5)), *x4 = calloc(1, sizeof(*x4));
        CHECK(s4 && x5 && x4, "alloc");
        CHECK(nodus_witness_storage_set_get(g_w, 5 * E_LEN, set) == 0 &&
              nodus_witness_storage_set_get(g_w, 4 * E_LEN, s4) == 0 &&
              rel_xor(set, 5 * E_LEN, x5) == 0 &&
              rel_xor(s4, 4 * E_LEN, x4) == 0, "XOR relations");
        for (unsigned m = 0; m < NMEM; m++) {
            uint64_t want[NSEG + 1], got[NSEG + 1];
            size_t nw = expect_ks(x5, x4, 5 * E_LEN, g_fp[m], want), ng = 0;
            CHECK(nodus_witness_sthold_must_hold(g_w, 5 * E_LEN, g_fp[m],
                      got, NSEG + 1, &ng) == 0 && same_list(want, nw, got, ng),
                  "H2: must-hold over the XOR relation, unchanged");
        }
        free(x4); free(x5); free(s4);
    }
    CHECK(nodus_witness_storage_set_get(g_w, 5 * E_LEN, set) == 0 &&
          rel_xor(set, 5 * E_LEN, prev) == 0, "XOR(set(H2))");

    /* B1 */
    uint64_t B = 6 * E_LEN;
    snprintf(g_ctx, sizeof(g_ctx), "B1");
    CHECK(freeze(B, 4, 1) == 0, "B1 freeze");
    CHECK(nodus_witness_storage_set_get(g_w, B, set) == 0 &&
          rel_hrw(set, 4, cur) == 0, "model");
    CHECK(check_paths(B, cur, prev, set, &grace_seen, last, last_n,
                      &changed) == 0, "B1 paths");
    CHECK(changed, "B1 changes the must-hold list of some member");
    memcpy(prev, cur, sizeof(*prev));

    /* a join */
    snprintf(g_ctx, sizeof(g_ctx), "join");
    CHECK(reg_put(10, 1, 0) == 0, "M10 registers");
    B += E_LEN;
    changed = 0;
    CHECK(freeze(B, 4, 1) == 0, "freeze");
    CHECK(nodus_witness_storage_set_get(g_w, B, set) == 0 &&
          rel_hrw(set, 4, cur) == 0, "model");
    CHECK(check_paths(B, cur, prev, set, &grace_seen, last, last_n,
                      &changed) == 0, "join paths");
    CHECK(changed, "the join changes a must-hold list");
    memcpy(prev, cur, sizeof(*prev));

    /* a departure and an eligibility crossing (overlap epoch: the leaver
     * still must-hold the previous epoch's segments) */
    snprintf(g_ctx, sizeof(g_ctx), "departure + crossing");
    CHECK(reg_put(3, 2, 0) == 0 && reg_put(5, 1, 3) == 0, "M3 exits, M5 3");
    B += E_LEN;
    changed = 0;
    CHECK(freeze(B, 4, 0) == 0, "freeze");
    CHECK(nodus_witness_storage_set_get(g_w, B, set) == 0 &&
          rel_hrw(set, 4, cur) == 0, "model");
    CHECK(check_paths(B, cur, prev, set, &grace_seen, last, last_n,
                      &changed) == 0, "departure paths");
    CHECK(changed, "the departure changes a must-hold list");
    memcpy(prev, cur, sizeof(*prev));

    /* R 4 -> 6 */
    snprintf(g_ctx, sizeof(g_ctx), "R 4 -> 6");
    B += E_LEN;
    CHECK(cc_row(DNAC_CFG_STORAGE_COPIES, 6, B, 3) == 0, "param 25");
    changed = 0;
    CHECK(freeze(B, 6, 0) == 0, "freeze");
    CHECK(nodus_witness_storage_set_get(g_w, B, set) == 0 &&
          rel_hrw(set, 6, cur) == 0, "model");
    CHECK(check_paths(B, cur, prev, set, &grace_seen, last, last_n,
                      &changed) == 0, "R paths");
    CHECK(changed, "the replica-count change changes a must-hold list");
    CHECK(grace_seen,
          "a member was in grace at some checked boundary (the grace case "
          "is exercised)");

    free(set); free(cur); free(prev);
    sqlite3_close(g_w->db);
    free(g_w);
    rmrf(g_dir);
    printf("test_storage_hrw_runtime: ALL %d checks passed\n", g_checks);
    return 0;
}
