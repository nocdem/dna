/**
 * @file nodus_witness_v2_storage.c
 * @brief Storage reward v1 rev 4 (the ARCHIVE reward), package B2a — the
 *        chain side. Contract, step order, the eligibility formula and
 *        the settlement rule: nodus_witness_v2_storage.h.
 *
 * Every function here runs inside the caller's block transaction and
 * opens / commits nothing. Every row iteration is an explicit ORDER BY on
 * a unique key; every amount is u64 with checked arithmetic (the weighted
 * share uses a 128-bit intermediate); no clock, no RNG, no hash-map
 * iteration. A malformed committed row is a FAULT, never "no data".
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_v2_storage.h"
#include "witness/nodus_witness_roots_v2.h"   /* registry loader           */
#include "witness/nodus_witness_v2_econ.h"    /* nodus_witness_v2_accrue   */
#include "witness/nodus_witness_v2_epoch.h"   /* snapshot authority,
                                               * release_utxo              */
#include "witness/nodus_witness_v2_claims.h"  /* v2_runtime_for            */
#include "witness/nodus_witness_v2_gen.h"     /* REWARD_DIVISOR_LOG2       */
#include "witness/nodus_witness_runtime.h"    /* NODUS_RT_GEN_STORAGE      */
#include "witness/nodus_witness_emission.h"   /* DNAC_DECIMAL_UNIT         */
#include "nodus/nodus_chain_config.h"

#include "dnac/dnac.h"
#include "dnac/res_meter.h"                   /* dna_ck_add/mul_u64        */
#include "dnac/vset_wire.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_fingerprint.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_u128.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "W_STORAGE"

/* The stored SQLite INTEGER bound (the V2EP_STORE_MAX rule). */
#define ST_STORE_MAX  ((uint64_t)INT64_MAX)

#define ST_P          ((uint64_t)DNA_V2_SEGMENT_BLOCKS)

_Static_assert(DNA_V2_SEGMENT_BLOCKS == 17280u,
               "archive bytes item 1: count = 17280");
_Static_assert(DNA_V2_STORAGE_HOLDERS == 3u && DNA_V2_STORAGE_FAIL_LIMIT == 3u,
               "decision 2026-10-05-storage-reward-is-for-archive: R = 3, "
               "skip at 3 failed epochs");
_Static_assert(DNAC_STORAGE_EXIT_LOCK_EPOCHS == 12,
               "design rev 2.2 F3: exit lock 12 epochs");
_Static_assert(DNAC_STORAGE_SEGMENT_DELAY_EPOCHS == 2,
               "design rev 4 §1: published at k·P + 2E");

/* ── small helpers ───────────────────────────────────────────────────── */

/* Is the column a BLOB of exactly `len` (> 0) bytes? (The storage class
 * is checked — never a TEXT that happens to have the length.) */
static int col_blob_len(sqlite3_stmt *st, int col, int len) {
    if (sqlite3_column_type(st, col) != SQLITE_BLOB) return 0;
    if (sqlite3_column_bytes(st, col) != len) return 0;
    return sqlite3_column_blob(st, col) != NULL;
}

static int col_int(sqlite3_stmt *st, int col, sqlite3_int64 lo,
                   sqlite3_int64 hi, sqlite3_int64 *out) {
    if (sqlite3_column_type(st, col) != SQLITE_INTEGER) return 0;
    sqlite3_int64 v = sqlite3_column_int64(st, col);
    if (v < lo || v > hi) return 0;
    *out = v;
    return 1;
}

/* floor(a × b / d) with a 128-bit intermediate. The caller guarantees
 * d != 0 and b <= d, so the quotient is <= a and fits 64 bits. */
static uint64_t st_muldiv(uint64_t a, uint64_t b, uint64_t d) {
    uint64_t rem = 0;
    qgp_u128_t num = qgp_u128_mul_u64(qgp_u128_from_u64(a), b);
    return qgp_u128_div_u64(num, d, &rem).lo;
}

/* Index of `fp` in the strictly ascending fps[0..n), or -1. */
static long st_find_fp(const uint8_t (*fps)[64], size_t n,
                       const uint8_t fp[64]) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = memcmp(fps[mid], fp, 64);
        if (c == 0) return (long)mid;
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    return -1;
}

/* Index of `fp` in the node_fp-ASC registry rows, or -1. */
static long st_find_row(const dna_v2_storage_node_row_t *rows, size_t n,
                        const uint8_t fp[64]) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = memcmp(rows[mid].node_fp, fp, 64);
        if (c == 0) return (long)mid;
        if (c < 0) lo = mid + 1;
        else hi = mid;
    }
    return -1;
}

static int st_exec1(nodus_witness_t *w, const char *sql, uint64_t a) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)a);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* ══════════════════════════════════════════════════════════════════════
 * Frozen sets
 * ════════════════════════════════════════════════════════════════════ */

int nodus_witness_storage_set_get(nodus_witness_t *w, uint64_t epoch_start,
                                  nodus_storage_set_t *out) {
    if (!w || !w->db || !out) return -1;
    if (epoch_start == 0 || epoch_start > ST_STORE_MAX) return 1;
    memset(out, 0, sizeof(*out));
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT set_hash, member_count FROM v2_storage_sets "
            "WHERE epoch_start = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)epoch_start);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) { sqlite3_finalize(st); return 1; }
    sqlite3_int64 cnt = 0;
    if (rc != SQLITE_ROW || !col_blob_len(st, 0, 64) ||
        !col_int(st, 1, 0, (sqlite3_int64)DNA_V2_STORAGE_SET_MAX, &cnt)) {
        sqlite3_finalize(st);
        QGP_LOG_ERROR(LOG_TAG, "storage set %llu: header row malformed or "
                      "unreadable", (unsigned long long)epoch_start);
        return -1;
    }
    memcpy(out->set_hash, sqlite3_column_blob(st, 0), 64);
    out->count = (uint32_t)cnt;
    out->epoch_start = epoch_start;
    sqlite3_finalize(st);

    st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT node_fp, fail_streak FROM v2_storage_set_members "
            "WHERE epoch_start = ?1 ORDER BY node_fp ASC",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)epoch_start);
    uint32_t n = 0;
    int bad = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        sqlite3_int64 fs = 0;
        if (n >= out->count || !col_blob_len(st, 0, 64) ||
            !col_int(st, 1, 0, (sqlite3_int64)UINT32_MAX, &fs)) {
            bad = 1;
            break;
        }
        memcpy(out->fps[n], sqlite3_column_blob(st, 0), 64);
        out->fail_streak[n] = (uint32_t)fs;
        n++;
    }
    sqlite3_finalize(st);
    if (bad || rc != SQLITE_DONE || n != out->count) {
        QGP_LOG_ERROR(LOG_TAG, "storage set %llu: members malformed (%u "
                      "rows for count %u)", (unsigned long long)epoch_start,
                      (unsigned)n, (unsigned)out->count);
        return -1;
    }
    /* the stored S(H) must be the members' S(H) — one derivation */
    uint8_t want[64];
    if (dna_v2_storage_set_hash(epoch_start,
                                (const uint8_t (*)[64])out->fps,
                                out->count, want) != 0 ||
        memcmp(want, out->set_hash, 64) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "storage set %llu: stored S(H) does not "
                      "re-derive from its members",
                      (unsigned long long)epoch_start);
        return -1;
    }
    return 0;
}

int nodus_witness_storage_sets_root(nodus_witness_t *w, uint8_t out[64]) {
    if (!w || !w->db || !out) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT epoch_start FROM v2_storage_sets ORDER BY epoch_start "
            "ASC", -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "sets root prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }
    size_t n = 0, cap = 4;
    uint64_t *hs = malloc(cap * sizeof(*hs));
    if (!hs) { sqlite3_finalize(st); return -1; }
    int rc, bad = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        sqlite3_int64 h = 0;
        if (!col_int(st, 0, 1, INT64_MAX, &h)) { bad = 1; break; }
        if (n == cap) {
            uint64_t *nh = realloc(hs, cap * 2 * sizeof(*hs));
            if (!nh) { bad = 1; break; }
            hs = nh;
            cap *= 2;
        }
        hs[n++] = (uint64_t)h;
    }
    sqlite3_finalize(st);
    if (bad || rc != SQLITE_DONE) { free(hs); return -1; }

    uint8_t (*sh)[64] = n ? malloc(n * sizeof(*sh)) : NULL;
    nodus_storage_set_t *set = calloc(1, sizeof(*set));
    int ret = -1;
    uint64_t members = 0;
    if ((n && !sh) || !set) goto done;
    for (size_t i = 0; i < n; i++) {
        if (nodus_witness_storage_set_get(w, hs[i], set) != 0) goto done;
        memcpy(sh[i], set->set_hash, 64);
        members += set->count;
    }
    /* no member row may live outside a header (an orphan would never be
     * committed by any root) */
    {
        sqlite3_stmt *c = NULL;
        if (sqlite3_prepare_v2(w->db, "SELECT COUNT(*) FROM "
                               "v2_storage_set_members", -1, &c, NULL)
            != SQLITE_OK)
            goto done;
        int crc = sqlite3_step(c);
        sqlite3_int64 cnt = crc == SQLITE_ROW ? sqlite3_column_int64(c, 0)
                                              : -1;
        sqlite3_finalize(c);
        if (cnt < 0 || (uint64_t)cnt != members) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "v2_storage_set_members holds "
                          "rows no set header names — failing root");
            goto done;
        }
    }
    ret = dna_v2_storage_sets_root(hs, (const uint8_t (*)[64])sh, n, out);
done:
    free(set);
    free(sh);
    free(hs);
    return ret;
}

/* ══════════════════════════════════════════════════════════════════════
 * Reports
 * ════════════════════════════════════════════════════════════════════ */

/* The reports of ONE epoch (epoch_start > 0) or of ALL epochs
 * (epoch_start == 0), (epoch_start, seat) ASC. *out malloc'd (NULL when
 * none). @return 0 / -1. */
static int st_reports_load(nodus_witness_t *w, uint64_t epoch_start,
                           dna_v2_storage_report_t **out, size_t *n_out) {
    *out = NULL;
    *n_out = 0;
    sqlite3_stmt *st = NULL;
    const char *sql = epoch_start
        ? "SELECT epoch_start, seat, set_hash, bitmap FROM "
          "v2_storage_reports WHERE epoch_start = ?1 ORDER BY seat ASC"
        : "SELECT epoch_start, seat, set_hash, bitmap FROM "
          "v2_storage_reports ORDER BY epoch_start ASC, seat ASC";
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "reports prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }
    if (epoch_start) sqlite3_bind_int64(st, 1, (sqlite3_int64)epoch_start);
    size_t n = 0, cap = 8;
    dna_v2_storage_report_t *r = malloc(cap * sizeof(*r));
    if (!r) { sqlite3_finalize(st); return -1; }
    int rc, bad = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        sqlite3_int64 h = 0, seat = 0;
        int blen = sqlite3_column_bytes(st, 3);
        if (!col_int(st, 0, 1, INT64_MAX, &h) ||
            !col_int(st, 1, 0, (sqlite3_int64)UINT32_MAX, &seat) ||
            !col_blob_len(st, 2, 64) ||
            sqlite3_column_type(st, 3) != SQLITE_BLOB ||
            blen < 0 || blen > (int)DNA_V2_STORAGE_BITMAP_MAX ||
            (blen > 0 && sqlite3_column_blob(st, 3) == NULL)) {
            bad = 1;
            break;
        }
        if (n == cap) {
            dna_v2_storage_report_t *nr = realloc(r, cap * 2 * sizeof(*r));
            if (!nr) { bad = 1; break; }
            r = nr;
            cap *= 2;
        }
        memset(&r[n], 0, sizeof(r[n]));
        r[n].epoch_start = (uint64_t)h;
        r[n].seat = (uint32_t)seat;
        memcpy(r[n].set_hash, sqlite3_column_blob(st, 2), 64);
        r[n].bitmap_len = (uint16_t)blen;
        if (blen > 0) memcpy(r[n].bitmap, sqlite3_column_blob(st, 3),
                             (size_t)blen);
        n++;
    }
    sqlite3_finalize(st);
    if (bad || rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "v2_storage_reports row malformed or "
                      "scan aborted");
        free(r);
        return -1;
    }
    if (n == 0) { free(r); r = NULL; }
    *out = r;
    *n_out = n;
    return 0;
}

int nodus_witness_storage_reports_root(nodus_witness_t *w, uint8_t out[64]) {
    if (!w || !w->db || !out) return -1;
    dna_v2_storage_report_t *r = NULL;
    size_t n = 0;
    if (st_reports_load(w, 0, &r, &n) != 0) return -1;
    int ret = dna_v2_storage_reports_root(r, n, out);
    free(r);
    return ret;
}

/* ══════════════════════════════════════════════════════════════════════
 * Segments
 * ════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint64_t k;
    uint8_t  root[64];
    uint64_t published_height;
} st_seg_t;

/* Every published segment with published_height <= max_pub (UINT64_MAX:
 * all), k ASC. The k's are exactly 1..n (contiguous publication) — any
 * gap is corrupt state. *out malloc'd (NULL when none). @return 0 / -1. */
static int st_segments_load(nodus_witness_t *w, uint64_t max_pub,
                            st_seg_t **out, size_t *n_out) {
    *out = NULL;
    *n_out = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT k, root, published_height FROM v2_storage_segments "
            "ORDER BY k ASC", -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "segments prepare failed: %s",
                      sqlite3_errmsg(w->db));
        return -1;
    }
    size_t n = 0, cap = 8;
    st_seg_t *s = malloc(cap * sizeof(*s));
    if (!s) { sqlite3_finalize(st); return -1; }
    int rc, bad = 0;
    uint64_t expect = 1;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        sqlite3_int64 k = 0, ph = 0;
        if (!col_int(st, 0, 1, INT64_MAX, &k) || !col_blob_len(st, 1, 64) ||
            !col_int(st, 2, 1, INT64_MAX, &ph) || (uint64_t)k != expect) {
            bad = 1;
            break;
        }
        expect++;
        if ((uint64_t)ph > max_pub) continue;
        if (n == cap) {
            st_seg_t *ns = realloc(s, cap * 2 * sizeof(*s));
            if (!ns) { bad = 1; break; }
            s = ns;
            cap *= 2;
        }
        s[n].k = (uint64_t)k;
        memcpy(s[n].root, sqlite3_column_blob(st, 1), 64);
        s[n].published_height = (uint64_t)ph;
        n++;
    }
    sqlite3_finalize(st);
    if (bad || rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "v2_storage_segments row malformed, "
                      "non-contiguous or scan aborted");
        free(s);
        return -1;
    }
    if (n == 0) { free(s); s = NULL; }
    *out = s;
    *n_out = n;
    return 0;
}

int nodus_witness_storage_segments_root(nodus_witness_t *w,
                                        uint8_t out[64]) {
    if (!w || !w->db || !out) return -1;
    st_seg_t *s = NULL;
    size_t n = 0;
    if (st_segments_load(w, UINT64_MAX, &s, &n) != 0) return -1;
    uint64_t *ks = n ? malloc(n * sizeof(*ks)) : NULL;
    uint8_t (*rs)[64] = n ? malloc(n * sizeof(*rs)) : NULL;
    int ret = -1;
    if (n == 0 || (ks && rs)) {
        for (size_t i = 0; i < n; i++) {
            ks[i] = s[i].k;
            memcpy(rs[i], s[i].root, 64);
        }
        ret = dna_v2_segments_root(ks, (const uint8_t (*)[64])rs, n, out);
    }
    free(rs);
    free(ks);
    free(s);
    return ret;
}

int nodus_witness_storage_segment_root_compute(nodus_witness_t *w,
                                               uint64_t k, uint8_t out[64]) {
    if (!w || !w->db || !out) return -1;
    if (k == 0 || k > ST_STORE_MAX / ST_P) return -1;
    const uint64_t first = (k - 1) * ST_P + 1, last = k * ST_P;
    uint8_t (*hashes)[64] = malloc((size_t)ST_P * 64);
    if (!hashes) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT global_height, block_id FROM v2_blocks "
            "WHERE global_height BETWEEN ?1 AND ?2 "
            "ORDER BY global_height ASC", -1, &st, NULL) != SQLITE_OK) {
        free(hashes);
        return -1;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)first);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)last);
    uint64_t expect = first;
    int rc, bad = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        sqlite3_int64 h = 0;
        /* a missing or malformed row is a FAULT (bytes item 1) */
        if (!col_int(st, 0, 0, INT64_MAX, &h) || (uint64_t)h != expect ||
            !col_blob_len(st, 1, 64)) {
            bad = 1;
            break;
        }
        memcpy(hashes[expect - first], sqlite3_column_blob(st, 1), 64);
        expect++;
    }
    sqlite3_finalize(st);
    if (bad || rc != SQLITE_DONE || expect != last + 1) {
        QGP_LOG_ERROR(LOG_TAG, "segment %llu: v2_blocks heights %llu..%llu "
                      "are missing or malformed on this node (stopped at "
                      "%llu)", (unsigned long long)k,
                      (unsigned long long)first, (unsigned long long)last,
                      (unsigned long long)expect);
        free(hashes);
        return -1;
    }
    int ret = dna_v2_segment_root(k, (const uint8_t (*)[64])hashes, out);
    free(hashes);
    return ret;
}

/* ══════════════════════════════════════════════════════════════════════
 * Assignment
 * ════════════════════════════════════════════════════════════════════ */

int nodus_witness_storage_holders(const nodus_storage_set_t *set,
                                  const uint8_t seg_root[64],
                                  uint8_t out_fps[DNA_V2_STORAGE_HOLDERS][64],
                                  size_t *n_out) {
    if (!set || !seg_root || !out_fps || !n_out) return -1;
    *n_out = 0;
    if (set->count > DNA_V2_STORAGE_SET_MAX) return -1;
    uint8_t a[64];
    size_t idx[DNA_V2_STORAGE_HOLDERS], n = 0;
    if (dna_v2_segment_assign_key(seg_root, a) != 0) return -1;
    if (dna_v2_segment_holders(a, (const uint8_t (*)[64])set->fps,
                               set->fail_streak, set->count, idx, &n) != 0)
        return -1;
    for (size_t i = 0; i < n; i++) memcpy(out_fps[i], set->fps[idx[i]], 64);
    *n_out = n;
    return 0;
}

/* Per-member eligible-segment marks for epoch (H, H+E] (header
 * "ELIGIBILITY"): for each segment published at or before H−E, its
 * holders over storage_set(H−E) that are members of storage_set(H).
 * `cur` = set(H); `prev` = set(H−E) (count 0 when absent); `segs` the
 * segments with published_height <= H−E. Calls `mark(ud, member_index,
 * k)` once per (member, eligible segment), k ascending.
 * @return 0 / -1. */
typedef int (*st_mark_fn)(void *ud, size_t member, uint64_t k);

static int st_eligible_walk(const nodus_storage_set_t *cur,
                            const nodus_storage_set_t *prev,
                            const st_seg_t *segs, size_t n_segs,
                            st_mark_fn mark, void *ud) {
    if (prev->count == 0 || cur->count == 0) return 0;
    for (size_t s = 0; s < n_segs; s++) {
        uint8_t hf[DNA_V2_STORAGE_HOLDERS][64];
        size_t nh = 0;
        if (nodus_witness_storage_holders(prev, segs[s].root, hf, &nh) != 0)
            return -1;
        for (size_t j = 0; j < nh; j++) {
            long m = st_find_fp((const uint8_t (*)[64])cur->fps, cur->count,
                                hf[j]);
            if (m < 0) continue;          /* left the set: no bit, no pay */
            if (mark(ud, (size_t)m, segs[s].k) != 0) return -1;
        }
    }
    return 0;
}

typedef struct {
    uint64_t weight[DNA_V2_STORAGE_SET_MAX];
} st_weights_t;

static int st_mark_weight(void *ud, size_t member, uint64_t k) {
    (void)k;
    st_weights_t *wt = ud;
    return dna_ck_add_u64(wt->weight[member], ST_P, &wt->weight[member]) == 0
               ? 0 : -1;
}

typedef struct {
    size_t    target;
    uint64_t *ks;
    size_t    cap, n;
} st_collect_t;

static int st_mark_collect(void *ud, size_t member, uint64_t k) {
    st_collect_t *c = ud;
    if (member != c->target) return 0;
    if (c->n < c->cap && c->ks) c->ks[c->n] = k;
    c->n++;
    return 0;
}

int nodus_witness_storage_eligible_segments(nodus_witness_t *w,
                                            uint64_t epoch_start,
                                            const uint8_t node_fp[64],
                                            uint64_t *ks_out, size_t cap,
                                            size_t *n_out) {
    if (!w || !w->db || !node_fp || !n_out) return -1;
    *n_out = 0;
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    if (epoch_start == 0 || (epoch_start % E) != 0) return -1;
    nodus_storage_set_t *cur = calloc(1, sizeof(*cur));
    nodus_storage_set_t *prev = calloc(1, sizeof(*prev));
    st_seg_t *segs = NULL;
    size_t n_segs = 0;
    int ret = -1;
    if (!cur || !prev) goto done;
    int rc = nodus_witness_storage_set_get(w, epoch_start, cur);
    if (rc != 0) { ret = rc == 1 ? 1 : -1; goto done; }
    rc = nodus_witness_storage_set_get(w, epoch_start - E, prev);
    if (rc < 0) goto done;
    if (rc == 1) prev->count = 0;
    long me = st_find_fp((const uint8_t (*)[64])cur->fps, cur->count,
                         node_fp);
    if (me < 0) { ret = 0; goto done; }
    if (st_segments_load(w, epoch_start - E, &segs, &n_segs) != 0)
        goto done;
    st_collect_t c = { (size_t)me, ks_out, cap, 0 };
    if (st_eligible_walk(cur, prev, segs, n_segs, st_mark_collect, &c) != 0)
        goto done;
    *n_out = c.n;
    ret = c.n <= cap ? 0 : -1;
done:
    free(segs);
    free(prev);
    free(cur);
    return ret;
}

int nodus_storage_eligible_height(const uint64_t *ks, size_t n,
                                  uint64_t position, uint64_t *height_out) {
    if (!ks || !height_out || n == 0) return -1;
    for (size_t i = 1; i < n; i++)
        if (ks[i - 1] >= ks[i]) return -1;
    const uint64_t seg = position / ST_P;
    if (seg >= (uint64_t)n) return -1;
    const uint64_t k = ks[seg];
    if (k == 0 || k > UINT64_MAX / ST_P) return -1;
    *height_out = (k - 1) * ST_P + 1 + position % ST_P;
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * The storage boundary
 * ════════════════════════════════════════════════════════════════════ */

/* Treasury pool 1, typed. @return 0 / -1 (absent = fault: a version-3
 * genesis seeds all nine pools). */
static int st_pool1_get(nodus_witness_t *w, uint64_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT balance FROM v2_treasury WHERE pool_id = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)NODUS_STORAGE_POOL_ID);
    int rc = sqlite3_step(st);
    sqlite3_int64 b = 0;
    int ok = rc == SQLITE_ROW && col_int(st, 0, 0, INT64_MAX, &b);
    sqlite3_finalize(st);
    if (!ok) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "treasury pool 1 (Storage) is absent "
                      "or malformed — refusing to settle");
        return -1;
    }
    *out = (uint64_t)b;
    return 0;
}

static int st_pool1_debit(nodus_witness_t *w, uint64_t observed,
                          uint64_t debit) {
    if (debit == 0) return 0;
    if (debit > observed) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "UPDATE v2_treasury SET balance = ?1 "
            "WHERE pool_id = ?2 AND balance = ?3", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)(observed - debit));
    sqlite3_bind_int64(st, 2, (sqlite3_int64)NODUS_STORAGE_POOL_ID);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)observed);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return (rc == SQLITE_DONE && sqlite3_changes(w->db) == 1) ? 0 : -1;
}

uint32_t nodus_storage_fail_streak_next(uint32_t old, int had_eligible,
                                        int ok) {
    if (old >= DNA_V2_STORAGE_FAIL_LIMIT) {          /* skipped (K5)      */
        if (old >= NODUS_STORAGE_FAIL_RETURN - 1u) return 0u;
        return old + 1u;
    }
    if (!had_eligible) return old;
    return ok ? 0u : old + 1u;
}

/* fail_streak := nv, bound to the observed value. */
static int st_streak_write(nodus_witness_t *w, const uint8_t fp[64],
                           uint32_t old, uint32_t nv) {
    if (old == nv) return 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "UPDATE v2_storage_nodes SET fail_streak = ?1 "
            "WHERE node_fp = ?2 AND fail_streak = ?3", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)nv);
    sqlite3_bind_blob(st, 2, fp, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)old);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return (rc == SQLITE_DONE && sqlite3_changes(w->db) == 1) ? 0 : -1;
}

/* STEP 1 — settle epoch (H, H+E], H = B − 2E. @return 0 / -2. */
static int st_settle(nodus_witness_t *w, uint64_t B,
                     nodus_storage_boundary_t *out) {
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    if (B < 3 * E) return 0;            /* H = B − 2E >= E: set(H) needs a
                                         * boundary H >= E               */
    const uint64_t H = B - 2 * E;

    int ret = -2;
    nodus_storage_set_t *cur = calloc(1, sizeof(*cur));
    nodus_storage_set_t *prev = calloc(1, sizeof(*prev));
    st_weights_t *wt = calloc(1, sizeof(*wt));
    st_seg_t *segs = NULL;
    size_t n_segs = 0;
    dna_vset_snapshot_t *snap = NULL;
    dna_v2_storage_report_t *reps = NULL;
    size_t n_reps = 0;
    dna_v2_storage_node_row_t *rows = NULL;
    size_t n_rows = 0;
    uint64_t *power = NULL;
    uint8_t (*seat_fp)[64] = NULL;
    const dna_v2_storage_report_t **by_seat = NULL;
    if (!cur || !prev || !wt) goto done;

    int rc = nodus_witness_storage_set_get(w, H, cur);
    if (rc == 1) { ret = 0; goto done; }  /* no set(H): first boundaries */
    if (rc != 0) goto done;
    rc = nodus_witness_storage_set_get(w, H - E, prev);
    if (rc < 0) goto done;
    if (rc == 1) prev->count = 0;         /* no set(H−E): all in grace   */

    /* ── weights (K1 block count) ─────────────────────────────────── */
    if (st_segments_load(w, H - E, &segs, &n_segs) != 0) goto done;
    if (st_eligible_walk(cur, prev, segs, n_segs, st_mark_weight, wt) != 0)
        goto done;
    uint64_t W = 0;
    for (uint32_t i = 0; i < cur->count; i++)
        if (dna_ck_add_u64(W, wt->weight[i], &W) != 0) goto done;

    /* ── snapshot(H): the reporting seats and their power ─────────── */
    if (nodus_witness_v2_epoch_authority_for_epoch(w, H, &snap, NULL,
                                                   NULL) != 0 || !snap) {
        QGP_LOG_ERROR(LOG_TAG, "settlement at %llu: snapshot(%llu) absent or "
                      "unreadable", (unsigned long long)B,
                      (unsigned long long)H);
        goto done;
    }
    const uint32_t n_seat = snap->active_count;
    power = calloc(n_seat, sizeof(*power));
    seat_fp = calloc(n_seat, sizeof(*seat_fp));
    by_seat = calloc(n_seat, sizeof(*by_seat));
    if (!power || !seat_fp || !by_seat) goto done;
    uint64_t P_total = 0;
    for (uint32_t s = 0; s < n_seat; s++) {
        power[s] = snap->entries[s].total_stake / (uint64_t)DNAC_DECIMAL_UNIT;
        if (dna_ck_add_u64(P_total, power[s], &P_total) != 0) goto done;
        if (qgp_sha3_512(snap->entries[s].pubkey, DNAC_PUBKEY_SIZE,
                         seat_fp[s]) != 0)
            goto done;
    }

    /* ── the committed reports for H (the exec admitted only these
     *    shapes, so any other is corrupt state: FAULT) ──────────────── */
    if (st_reports_load(w, H, &reps, &n_reps) != 0) goto done;
    const uint16_t want_bl = (uint16_t)((cur->count + 7u) / 8u);
    uint64_t P_rep = 0;
    for (size_t r = 0; r < n_reps; r++) {
        const dna_v2_storage_report_t *rp = &reps[r];
        if (rp->seat >= n_seat || memcmp(rp->set_hash, cur->set_hash, 64) ||
            rp->bitmap_len != want_bl || by_seat[rp->seat]) {
            QGP_LOG_ERROR(LOG_TAG, "settlement at %llu: committed report "
                          "(seat %u) does not fit storage_set(%llu) — "
                          "corrupt", (unsigned long long)B,
                          (unsigned)rp->seat, (unsigned long long)H);
            goto done;
        }
        if ((cur->count % 8u) != 0 && want_bl > 0 &&
            (rp->bitmap[want_bl - 1] >> (cur->count % 8u)) != 0)
            goto done;                    /* unused high bits set        */
        by_seat[rp->seat] = rp;
        if (dna_ck_add_u64(P_rep, power[rp->seat], &P_rep) != 0) goto done;
    }

    /* ── F1: reports from MORE THAN 1/2 of total power, else nothing
     *    moves for that epoch (no pay, no fail_streak) ──────────────── */
    {
        uint64_t twice = 0;
        if (dna_ck_mul_u64(P_rep, 2, &twice) != 0) goto done;
        if (!(twice > P_total)) { ret = 0; goto done; }
    }
    out->settled = 1;

    /* ── per-member verdict (F2 + the > 2/3 test) ─────────────────── */
    uint8_t ok[DNA_V2_STORAGE_SET_MAX];
    memset(ok, 0, sizeof(ok));
    for (uint32_t i = 0; i < cur->count; i++) {
        long self = -1;
        for (uint32_t s = 0; s < n_seat; s++) {
            if (memcmp(seat_fp[s], cur->fps[i], 64) != 0) continue;
            if (self >= 0) goto done;     /* two seats, one key: corrupt */
            self = (long)s;
        }
        uint64_t prep = P_rep;
        if (self >= 0 && by_seat[self]) prep -= power[self];   /* F2 */
        uint64_t yes = 0;
        for (uint32_t s = 0; s < n_seat; s++) {
            if (!by_seat[s] || (long)s == self) continue;  /* F2: own bit */
            if ((by_seat[s]->bitmap[i / 8u] >> (i % 8u)) & 1u)
                if (dna_ck_add_u64(yes, power[s], &yes) != 0) goto done;
        }
        uint64_t y3 = 0, p2 = 0;
        if (dna_ck_mul_u64(yes, 3, &y3) != 0 ||
            dna_ck_mul_u64(prep, 2, &p2) != 0)
            goto done;
        ok[i] = y3 > p2 ? 1u : 0u;
    }

    /* ── the registry rows of the members (payee, live fail_streak) ── */
    if (nodus_witness_storage_registry_load(w, &rows, &n_rows) != 0)
        goto done;
    long row_of[DNA_V2_STORAGE_SET_MAX];
    for (uint32_t i = 0; i < cur->count; i++) {
        row_of[i] = st_find_row(rows, n_rows, cur->fps[i]);
        if (row_of[i] < 0) {              /* registry rows never vanish */
            QGP_LOG_ERROR(LOG_TAG, "settlement at %llu: a member of "
                          "storage_set(%llu) has no registry row",
                          (unsigned long long)B, (unsigned long long)H);
            goto done;
        }
    }

    /* ── weighted pay from pool 1 (W == 0 → nothing) ──────────────── */
    if (W > 0) {
        uint64_t pool1 = 0;
        if (st_pool1_get(w, &pool1) != 0) goto done;
        const uint64_t budget = pool1 >> NODUS_V2_GEN_REWARD_DIVISOR_LOG2;
        uint64_t total = 0;
        for (uint32_t i = 0; i < cur->count && budget > 0; i++) {
            if (!ok[i] || wt->weight[i] == 0) continue;
            if (wt->weight[i] > W) goto done;
            const uint64_t share = st_muldiv(budget, wt->weight[i], W);
            if (share == 0) continue;
            if (nodus_witness_v2_accrue(w, rows[row_of[i]].payee_fp, share)
                != 0)
                goto done;
            if (dna_ck_add_u64(total, share, &total) != 0) goto done;
            out->n_paid++;
        }
        if (total > budget) goto done;    /* Σ floor(shares) <= budget   */
        if (st_pool1_debit(w, pool1, total) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "settlement at %llu: the pool 1 debit "
                          "did not land", (unsigned long long)B);
            goto done;
        }
        out->accrued = total;
    }

    /* ── fail_streak (bytes item 4 + K5) — below 3 only members with an
     *    eligible block move (OK resets, NOT OK adds one); at 3 or more
     *    every member adds one, and 15 is reset to 0 ─────────────────── */
    for (uint32_t i = 0; i < cur->count; i++) {
        const uint32_t old = rows[row_of[i]].fail_streak;
        const uint32_t nv = nodus_storage_fail_streak_next(
                                old, wt->weight[i] > 0, ok[i]);
        if (st_streak_write(w, cur->fps[i], old, nv) != 0) goto done;
    }
    ret = 0;

done:
    free(rows);
    free(by_seat);
    free(seat_fp);
    free(power);
    free(reps);
    dna_vset_free(&snap);
    free(segs);
    free(wt);
    free(prev);
    free(cur);
    return ret;
}

/* STEP 2 — prune what the settlement just consumed. @return 0 / -2. */
static int st_prune(nodus_witness_t *w, uint64_t B) {
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    if (B < 2 * E) return 0;
    const uint64_t H = B - 2 * E;
    if (st_exec1(w, "DELETE FROM v2_storage_reports WHERE epoch_start <= ?1",
                 H) != 0 ||
        st_exec1(w, "DELETE FROM v2_storage_set_members WHERE "
                 "epoch_start < ?1", H) != 0 ||
        st_exec1(w, "DELETE FROM v2_storage_sets WHERE epoch_start < ?1",
                 H) != 0)
        return -2;
    return 0;
}

/* STEP 3 — release every EXITING row (bytes 2026-10-04 item 6).
 * @return 0 / -2. */
static int st_release(nodus_witness_t *w, uint64_t B,
                      const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                      nodus_storage_boundary_t *out) {
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    uint64_t lock = 0, unlock = 0;
    if (dna_ck_mul_u64((uint64_t)DNAC_STORAGE_EXIT_LOCK_EPOCHS, E, &lock)
            != 0 ||
        dna_ck_add_u64(B, lock, &unlock) != 0 || unlock > ST_STORE_MAX)
        return -2;
    dna_v2_storage_node_row_t *rows = NULL;
    size_t n = 0;
    if (nodus_witness_storage_registry_load(w, &rows, &n) != 0) return -2;
    int ret = -2;
    for (size_t i = 0; i < n; i++) {         /* node_fp ASC */
        if (rows[i].status != DNA_V2_STORAGE_EXITING) continue;
        if (rows[i].bond == 0) goto done;    /* exec writes the exact bond */
        uint8_t exit_id[64], nul[64];
        char hex[QGP_FP_HEX_BUFFER];
        if (dna_v2_storage_exit_id(chain_id, B, rows[i].node_fp,
                                   exit_id) != 0 ||
            dna_v2_storage_exit_nullifier(exit_id, nul) != 0)
            goto done;
        qgp_fp_raw_to_hex(rows[i].payee_fp, hex);
        if (nodus_witness_v2_epoch_release_utxo(
                w, nul, exit_id, DNA_V2_STORAGE_EXIT_OUT_IDX,
                (const uint8_t *)hex, rows[i].bond, B, unlock) != 0)
            goto done;
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "UPDATE v2_storage_nodes SET status = ?1 "
                "WHERE node_fp = ?2 AND status = ?3", -1, &st, NULL)
            != SQLITE_OK)
            goto done;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)DNA_V2_STORAGE_RELEASED);
        sqlite3_bind_blob(st, 2, rows[i].node_fp, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)DNA_V2_STORAGE_EXITING);
        int rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE || sqlite3_changes(w->db) != 1) goto done;
        out->n_released++;
    }
    ret = 0;
done:
    free(rows);
    return ret;
}

/* STEP 4 — publish every due segment. @return 0 / -2. */
static int st_publish(nodus_witness_t *w, uint64_t B,
                      nodus_storage_boundary_t *out) {
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    uint64_t delay = 0;
    if (dna_ck_mul_u64((uint64_t)DNAC_STORAGE_SEGMENT_DELAY_EPOCHS, E,
                       &delay) != 0)
        return -2;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "SELECT COUNT(*), COALESCE(MAX(k), 0) "
                           "FROM v2_storage_segments", -1, &st, NULL)
        != SQLITE_OK)
        return -2;
    int rc = sqlite3_step(st);
    sqlite3_int64 cnt = rc == SQLITE_ROW ? sqlite3_column_int64(st, 0) : -1;
    sqlite3_int64 mx = rc == SQLITE_ROW ? sqlite3_column_int64(st, 1) : -1;
    sqlite3_finalize(st);
    if (cnt < 0 || mx != cnt) {           /* 1..max, contiguous          */
        QGP_LOG_ERROR(LOG_TAG, "%s", "v2_storage_segments is not the "
                      "contiguous list 1..max — corrupt");
        return -2;
    }
    for (uint64_t k = (uint64_t)mx + 1;; k++) {
        if (k > ST_STORE_MAX / ST_P) return -2;
        uint64_t due = 0;
        if (dna_ck_add_u64(k * ST_P, delay, &due) != 0) return -2;
        if (due > B) break;               /* immature: never published   */
        uint8_t root[64];
        if (nodus_witness_storage_segment_root_compute(w, k, root) != 0)
            return -2;
        st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO v2_storage_segments (k, root, "
                "published_height) VALUES (?1, ?2, ?3)", -1, &st, NULL)
            != SQLITE_OK)
            return -2;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)k);
        sqlite3_bind_blob(st, 2, root, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)B);
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) return -2;
        out->n_published++;
    }
    return 0;
}

int nodus_witness_storage_publish_due(nodus_witness_t *w,
                                      uint64_t boundary_height,
                                      uint32_t *n_out) {
    if (!w || !w->db || !n_out) return -1;
    *n_out = 0;
    nodus_storage_boundary_t sb;
    memset(&sb, 0, sizeof(sb));
    if (st_publish(w, boundary_height, &sb) != 0) return -1;
    *n_out = sb.n_published;
    return 0;
}

/* STEP 5 — freeze storage_set(B). @return 0 / -2. */
static int st_freeze(nodus_witness_t *w, uint64_t B,
                     nodus_storage_boundary_t *out) {
    if (B > ST_STORE_MAX) return -2;
    dna_v2_storage_node_row_t *rows = NULL;
    size_t n = 0;
    if (nodus_witness_storage_registry_load(w, &rows, &n) != 0) return -2;
    int ret = -2;
    nodus_storage_set_t *set = calloc(1, sizeof(*set));
    if (!set) goto done;
    for (size_t i = 0; i < n; i++) {         /* node_fp ASC */
        if (rows[i].status != DNA_V2_STORAGE_ACTIVE) continue;
        if (set->count >= DNA_V2_STORAGE_SET_MAX) goto done;   /* cap */
        memcpy(set->fps[set->count], rows[i].node_fp, 64);
        set->fail_streak[set->count] = rows[i].fail_streak;
        set->count++;
    }
    if (dna_v2_storage_set_hash(B, (const uint8_t (*)[64])set->fps,
                                set->count, set->set_hash) != 0)
        goto done;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_storage_sets (epoch_start, set_hash, "
            "member_count) VALUES (?1, ?2, ?3)", -1, &st, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)B);
    sqlite3_bind_blob(st, 2, set->set_hash, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)set->count);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) goto done;        /* an existing set(B): fault */
    for (uint32_t i = 0; i < set->count; i++) {
        st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO v2_storage_set_members (epoch_start, node_fp, "
                "fail_streak) VALUES (?1, ?2, ?3)", -1, &st, NULL)
            != SQLITE_OK)
            goto done;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)B);
        sqlite3_bind_blob(st, 2, set->fps[i], 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)set->fail_streak[i]);
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) goto done;
    }
    out->set_count = set->count;
    ret = 0;
done:
    free(set);
    free(rows);
    return ret;
}

int nodus_witness_storage_boundary_apply(
        nodus_witness_t *w, uint64_t boundary_height,
        const uint8_t chain_id[DNA_CHAIN_ID_LEN],
        nodus_storage_boundary_t *out) {
    if (!w || !w->db || !chain_id || !out) return -2;
    memset(out, 0, sizeof(*out));
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    const uint64_t B = boundary_height;
    if (B == 0 || (B % E) != 0) return 0;

    /* ── 0. GATE: param 14 in effect at B, read FIRST ──────────────── */
    {
        uint64_t v = 0;
        int rc = nodus_chain_config_get_u64(
                     w, (uint8_t)DNAC_CFG_RULESET_GEN_STORAGE, B, 0ULL, &v);
        if (rc < 0) {
            QGP_LOG_ERROR(LOG_TAG, "storage boundary %llu: the "
                          "RULESET_GEN_STORAGE history is unreadable",
                          (unsigned long long)B);
            return -2;
        }
        if (rc != 0) return 0;             /* before H_act: not active    */
        const nodus_domain_runtime_t *rt = NULL;
        if (nodus_witness_v2_runtime_for(w, DNA_DOMAIN_SYSTEM, 1, &rt) != 0
            || !rt) {
            QGP_LOG_ERROR(LOG_TAG, "storage boundary %llu: the SYSTEM "
                          "runtime does not resolve",
                          (unsigned long long)B);
            return -2;
        }
        if (rt->generation < NODUS_RT_GEN_STORAGE) {
            QGP_LOG_ERROR(LOG_TAG, "storage boundary %llu: param 14 is in "
                          "effect but the SYSTEM runtime is generation %u",
                          (unsigned long long)B, (unsigned)rt->generation);
            return -2;
        }
    }
    out->active = 1;

    if (st_settle(w, B, out) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "storage settlement failed at %llu",
                      (unsigned long long)B);
        return -2;
    }
    if (st_prune(w, B) != 0 ||
        st_release(w, B, chain_id, out) != 0 ||
        st_publish(w, B, out) != 0 ||
        st_freeze(w, B, out) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "storage boundary maintenance failed at %llu",
                      (unsigned long long)B);
        return -2;
    }
    QGP_LOG_DEBUG(LOG_TAG, "storage boundary %llu: settled %d, accrued %llu "
                  "to %u, released %u, published %u, set %u",
                  (unsigned long long)B, out->settled,
                  (unsigned long long)out->accrued, (unsigned)out->n_paid,
                  (unsigned)out->n_released, (unsigned)out->n_published,
                  (unsigned)out->set_count);
    return 0;
}
