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
#include "witness/nodus_witness_vset.h"       /* HF-6 5b: the power helper */
#include "witness/nodus_witness_validator.h"  /* HF-6 6b-2: the v1 bridge  */
#include "nodus/nodus_chain_config.h"

#include "dnac/dnac.h"
#include "dnac/res_meter.h"                   /* dna_ck_add/mul_u64        */
#include "dnac/vset_wire.h"
#include "dnac/valbind_wire.h"                /* dna_validator_id_migrated */

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

/* P = 24 epochs; 17280 at the shipped E = 720 (archive bytes item 1),
 * asserted where it is defined (shared/dnac/ledger_roots_v2.c). The
 * short-epoch test build (E = 15) runs P = 360. */
_Static_assert(DNA_V2_SEGMENT_BLOCKS == 24u * (uint64_t)DNAC_EPOCH_LENGTH,
               "a segment is one payday period of 24 epochs");
_Static_assert(DNA_V2_STORAGE_HOLDERS == 3u && DNA_V2_STORAGE_FAIL_LIMIT == 3u,
               "decision 2026-10-05-storage-reward-is-for-archive: R = 3, "
               "skip at 3 failed epochs");
/* HF-9 plan §8.7: the buffers hold the generation-6 capacities, which must
 * cover the param-25 maximum and the member cap's bitmap; the historical
 * constants above keep governing every generation <= 5 path. */
_Static_assert(DNA_V2_STORAGE_HOLDERS_CAP >= DNAC_CFG_MAX_STORAGE_COPIES,
               "the holder buffers hold the largest param-25 value");
_Static_assert(DNA_V2_STORAGE_BITMAP_CAP ==
                   (DNA_V2_STORAGE_SET_CAP + 7u) / 8u,
               "the bitmap capacity is ceil(member capacity / 8)");
_Static_assert(DNA_V2_STORAGE_SET_CAP >= DNA_V2_STORAGE_SET_MAX &&
               DNA_V2_STORAGE_BITMAP_CAP >= DNA_V2_STORAGE_BITMAP_MAX,
               "the capacities cover the historical limits");
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

nodus_storage_work_t g_nodus_storage_work;

/* ══════════════════════════════════════════════════════════════════════
 * Generation-6 regime and limits (HF-9 plan §8.6, §8.7)
 * ════════════════════════════════════════════════════════════════════ */

int nodus_witness_storage_gen6_at(nodus_witness_t *w, uint64_t height) {
    if (!w || !w->db) return -1;
    uint64_t v = 0;
    int rc = nodus_chain_config_get_u64(
                 w, (uint8_t)DNAC_CFG_RULESET_GEN_TRIE, height, 0ULL, &v);
    if (rc < 0) return -1;
    return rc == 0 ? 1 : 0;           /* 0 = a row in effect, 1 = none     */
}

int nodus_witness_storage_limits_at(nodus_witness_t *w, uint64_t epoch_start,
                                    uint32_t *set_cap_out,
                                    uint32_t *bitmap_cap_out) {
    int g = nodus_witness_storage_gen6_at(w, epoch_start);
    if (g < 0 || !set_cap_out || !bitmap_cap_out) return -1;
    *set_cap_out = g ? DNA_V2_STORAGE_SET_LIMIT_GEN6
                     : DNA_V2_STORAGE_SET_MAX;
    *bitmap_cap_out = g ? DNA_V2_STORAGE_BITMAP_LIMIT_GEN6
                        : DNA_V2_STORAGE_BITMAP_MAX;
    return 0;
}

int nodus_witness_storage_copies_at(nodus_witness_t *w, uint64_t boundary,
                                    uint32_t *copies_out) {
    if (!w || !w->db || !copies_out) return -1;
    uint64_t v = 0;
    int rc = nodus_chain_config_get_u64(
                 w, (uint8_t)DNAC_CFG_STORAGE_COPIES, boundary,
                 (uint64_t)DNAC_STORAGE_COPIES_DEFAULT, &v);
    if (rc < 0) return -1;
    if (v < (uint64_t)DNAC_CFG_MIN_STORAGE_COPIES ||
        v > (uint64_t)DNAC_CFG_MAX_STORAGE_COPIES) {
        QGP_LOG_ERROR(LOG_TAG, "param 25 (copies) reads %llu at %llu, "
                      "outside [%u, %u] - corrupt chain_config",
                      (unsigned long long)v, (unsigned long long)boundary,
                      (unsigned)DNAC_CFG_MIN_STORAGE_COPIES,
                      (unsigned)DNAC_CFG_MAX_STORAGE_COPIES);
        return -1;
    }
    *copies_out = (uint32_t)v;
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * Retained-assignment tables (plan §8.4, AD-6): derived node state written
 * inside the block transaction, in no root. Every accessor is typed and a
 * malformed / unreadable row is a FAULT (-1), never "empty".
 * ════════════════════════════════════════════════════════════════════ */

#define ST_R_CAP  DNA_V2_STORAGE_HOLDERS_CAP

/* The assignment state row. *present = 0 when no row (before E-s2).
 * @return 0 / -1. */
static int st_state_get(nodus_witness_t *w, int *present, uint32_t *copies,
                        uint64_t *boundary, int *xfer) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT copies, boundary, xfer FROM v2_storage_assign_state "
            "WHERE id = 1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    int ret = -1;
    if (rc == SQLITE_DONE) {
        *present = 0;
        ret = 0;
    } else if (rc == SQLITE_ROW) {
        sqlite3_int64 c = 0, b = 0, x = 0;
        if (col_int(st, 0, 1, (sqlite3_int64)ST_R_CAP, &c) &&
            col_int(st, 1, 0, INT64_MAX, &b) && col_int(st, 2, 0, 1, &x) &&
            sqlite3_step(st) == SQLITE_DONE) {
            *present = 1;
            *copies = (uint32_t)c;
            *boundary = (uint64_t)b;
            *xfer = (int)x;
            ret = 0;
        }
    }
    sqlite3_finalize(st);
    return ret;
}

/* The members the current rows reflect, node_fp ASC; at most `cap`.
 * @return 0 / -1. */
static int st_basis_load(nodus_witness_t *w, uint8_t (*fps)[64], size_t cap,
                         size_t *n_out) {
    sqlite3_stmt *st = NULL;
    *n_out = 0;
    if (sqlite3_prepare_v2(w->db,
            "SELECT node_fp FROM v2_storage_assign_basis "
            "ORDER BY node_fp ASC", -1, &st, NULL) != SQLITE_OK)
        return -1;
    size_t n = 0;
    int rc, bad = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (n >= cap || !col_blob_len(st, 0, 64) ||
            (n > 0 && memcmp(fps[n - 1], sqlite3_column_blob(st, 0), 64)
                          >= 0)) {
            bad = 1;
            break;
        }
        memcpy(fps[n++], sqlite3_column_blob(st, 0), 64);
    }
    sqlite3_finalize(st);
    if (bad || rc != SQLITE_DONE) return -1;
    *n_out = n;
    return 0;
}

/* Write the state row; replace the basis with fps[0..n) when `rewrite`.
 * @return 0 / -1. */
static int st_basis_store(nodus_witness_t *w, int rewrite,
                          const uint8_t (*fps)[64], size_t n,
                          uint32_t copies, uint64_t boundary, int xfer) {
    if (rewrite) {
        if (sqlite3_exec(w->db, "DELETE FROM v2_storage_assign_basis", NULL,
                         NULL, NULL) != SQLITE_OK)
            return -1;
        for (size_t i = 0; i < n; i++) {
            sqlite3_stmt *st = NULL;
            if (sqlite3_prepare_v2(w->db,
                    "INSERT INTO v2_storage_assign_basis (node_fp) VALUES "
                    "(?1)", -1, &st, NULL) != SQLITE_OK)
                return -1;
            sqlite3_bind_blob(st, 1, fps[i], 64, SQLITE_STATIC);
            int rc = sqlite3_step(st);
            sqlite3_finalize(st);
            if (rc != SQLITE_DONE) return -1;
        }
    }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT OR REPLACE INTO v2_storage_assign_state "
            "(id, copies, boundary, xfer) VALUES (1, ?1, ?2, ?3)", -1, &st,
            NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)copies);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)boundary);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)xfer);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* The CURRENT rows of segment k (to_h IS NULL; the literal predicate makes
 * the partial index applicable), node_fp ASC, with their stored scores.
 * More than ST_R_CAP rows is corrupt. @return 0 / -1. */
static int st_rows_cur(nodus_witness_t *w, uint64_t k,
                       uint8_t fp[ST_R_CAP][64], uint8_t sc[ST_R_CAP][64],
                       size_t *n_out) {
    sqlite3_stmt *st = NULL;
    *n_out = 0;
    if (sqlite3_prepare_v2(w->db,
            "SELECT node_fp, score FROM v2_storage_assign WHERE k = ?1 AND "
            "to_h IS NULL ORDER BY node_fp ASC", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)k);
    size_t n = 0;
    int rc, bad = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (n >= ST_R_CAP || !col_blob_len(st, 0, 64) ||
            !col_blob_len(st, 1, 64)) {
            bad = 1;
            break;
        }
        memcpy(fp[n], sqlite3_column_blob(st, 0), 64);
        memcpy(sc[n], sqlite3_column_blob(st, 1), 64);
        n++;
    }
    sqlite3_finalize(st);
    if (bad || rc != SQLITE_DONE) return -1;
    g_nodus_storage_work.assign_rows_read += n;
    *n_out = n;
    return 0;
}

static int st_row_insert(nodus_witness_t *w, uint64_t k,
                         const uint8_t fp[64], const uint8_t score[64],
                         uint64_t from_h) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_storage_assign (k, node_fp, score, from_h, "
            "to_h) VALUES (?1, ?2, ?3, ?4, NULL)", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)k);
    sqlite3_bind_blob(st, 2, fp, 64, SQLITE_STATIC);
    sqlite3_bind_blob(st, 3, score, 64, SQLITE_STATIC);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)from_h);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;
    g_nodus_storage_work.assign_rows_written++;
    return 0;
}

/* End the current row of (k, fp): to_h = `to_h`. Rows are ended, never
 * deleted (D6). @return 0 / -1 (no current row = corrupt). */
static int st_row_end(nodus_witness_t *w, uint64_t k, const uint8_t fp[64],
                      uint64_t to_h) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "UPDATE v2_storage_assign SET to_h = ?3 WHERE k = ?1 AND "
            "node_fp = ?2 AND to_h IS NULL", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)k);
    sqlite3_bind_blob(st, 2, fp, 64, SQLITE_STATIC);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)to_h);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE || sqlite3_changes(w->db) != 1) return -1;
    g_nodus_storage_work.assign_rows_written++;
    return 0;
}

/* held(node_fp): the number of current rows; 0 when the member has no row
 * (the table keeps only members with held >= 1). @return 0 / -1. */
static int st_held_get(nodus_witness_t *w, const uint8_t fp[64],
                       uint64_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT held FROM v2_storage_held WHERE node_fp = ?1", -1, &st,
            NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, fp, 64, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    int ret = -1;
    if (rc == SQLITE_DONE) {
        *out = 0;
        ret = 0;
    } else if (rc == SQLITE_ROW) {
        sqlite3_int64 h = 0;
        if (col_int(st, 0, 1, INT64_MAX, &h) &&
            sqlite3_step(st) == SQLITE_DONE) {
            *out = (uint64_t)h;
            ret = 0;
        }
    }
    sqlite3_finalize(st);
    return ret;
}

/* held(node_fp) += delta; a result of 0 removes the row, a negative one is
 * corrupt. @return 0 / -1. */
static int st_held_add(nodus_witness_t *w, const uint8_t fp[64],
                       int delta) {
    uint64_t cur = 0;
    if (st_held_get(w, fp, &cur) != 0) return -1;
    if (delta < 0 && cur < (uint64_t)(-delta)) return -1;
    const uint64_t nv = delta < 0 ? cur - (uint64_t)(-delta)
                                  : cur + (uint64_t)delta;
    sqlite3_stmt *st = NULL;
    if (nv == 0) {
        if (cur == 0) return 0;
        if (sqlite3_prepare_v2(w->db,
                "DELETE FROM v2_storage_held WHERE node_fp = ?1", -1, &st,
                NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_blob(st, 1, fp, 64, SQLITE_STATIC);
    } else {
        if (nv > (uint64_t)INT64_MAX) return -1;
        if (sqlite3_prepare_v2(w->db,
                "INSERT OR REPLACE INTO v2_storage_held (node_fp, held) "
                "VALUES (?1, ?2)", -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_blob(st, 1, fp, 64, SQLITE_STATIC);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)nv);
    }
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int st_member_epoch_put(nodus_witness_t *w, uint64_t epoch_start,
                               const uint8_t fp[64], uint64_t held_union,
                               uint64_t n_new) {
    if (held_union > (uint64_t)INT64_MAX || n_new > (uint64_t)INT64_MAX)
        return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_storage_member_epoch (epoch_start, node_fp, "
            "held_union, n_new) VALUES (?1, ?2, ?3, ?4)", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)epoch_start);
    sqlite3_bind_blob(st, 2, fp, 64, SQLITE_STATIC);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)held_union);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)n_new);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* @return 0 found / 1 absent / -1 fault (or a malformed row). */
static int st_member_epoch_get(nodus_witness_t *w, uint64_t epoch_start,
                               const uint8_t fp[64], uint64_t *held_union,
                               uint64_t *n_new) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT held_union, n_new FROM v2_storage_member_epoch WHERE "
            "epoch_start = ?1 AND node_fp = ?2", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)epoch_start);
    sqlite3_bind_blob(st, 2, fp, 64, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    int ret = -1;
    if (rc == SQLITE_DONE) {
        ret = 1;
    } else if (rc == SQLITE_ROW) {
        sqlite3_int64 hu = 0, nn = 0;
        if (col_int(st, 0, 0, INT64_MAX, &hu) &&
            col_int(st, 1, 0, INT64_MAX, &nn) &&
            sqlite3_step(st) == SQLITE_DONE) {
            *held_union = (uint64_t)hu;
            *n_new = (uint64_t)nn;
            ret = 0;
        }
    }
    sqlite3_finalize(st);
    return ret;
}

/* ══════════════════════════════════════════════════════════════════════
 * Frozen sets
 * ════════════════════════════════════════════════════════════════════ */

int nodus_witness_storage_set_get(nodus_witness_t *w, uint64_t epoch_start,
                                  nodus_storage_set_t *out) {
    if (!w || !w->db || !out) return -1;
    if (epoch_start == 0 || epoch_start > ST_STORE_MAX) return 1;
    uint32_t set_cap = 0, bm_cap = 0;
    if (nodus_witness_storage_limits_at(w, epoch_start, &set_cap, &bm_cap)
        != 0)
        return -1;
    (void)bm_cap;
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
        !col_int(st, 1, 0, (sqlite3_int64)set_cap, &cnt)) {
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
            "SELECT node_fp, fail_streak, grace_until FROM "
            "v2_storage_set_members WHERE epoch_start = ?1 "
            "ORDER BY node_fp ASC", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)epoch_start);
    uint32_t n = 0;
    int bad = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        sqlite3_int64 fs = 0, gu = 0;
        if (n >= out->count || !col_blob_len(st, 0, 64) ||
            !col_int(st, 1, 0, (sqlite3_int64)UINT32_MAX, &fs) ||
            !col_int(st, 2, 0, INT64_MAX, &gu)) {
            bad = 1;
            break;
        }
        memcpy(out->fps[n], sqlite3_column_blob(st, 0), 64);
        out->fail_streak[n] = (uint32_t)fs;
        out->grace_until[n] = (uint64_t)gu;
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
    if (dna_v2_storage_set_hash_lim(epoch_start,
                                    (const uint8_t (*)[64])out->fps,
                                    out->count, set_cap, want) != 0 ||
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
    uint64_t lim_epoch = 0;               /* memo of the last epoch's limit */
    uint32_t lim_bm = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        sqlite3_int64 h = 0, seat = 0;
        int blen = sqlite3_column_bytes(st, 3);
        if (!col_int(st, 0, 1, INT64_MAX, &h) ||
            !col_int(st, 1, 0, (sqlite3_int64)UINT32_MAX, &seat) ||
            !col_blob_len(st, 2, 64) ||
            sqlite3_column_type(st, 3) != SQLITE_BLOB ||
            blen < 0 || (blen > 0 && sqlite3_column_blob(st, 3) == NULL)) {
            bad = 1;
            break;
        }
        /* the bitmap limit of the report's own epoch (HF-9 §8.7): 32 up to
         * generation 5, 128 from 6 */
        if ((uint64_t)h != lim_epoch || lim_bm == 0) {
            uint32_t sc = 0;
            if (nodus_witness_storage_limits_at(w, (uint64_t)h, &sc,
                                                &lim_bm) != 0) {
                bad = 1;
                break;
            }
            lim_epoch = (uint64_t)h;
        }
        if ((uint32_t)blen > lim_bm) {
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
    /* st_reports_load has already held every row to ITS epoch's bitmap
     * limit (32 / 128); the root hashes the rows as they are, up to the
     * capacity */
    int ret = dna_v2_storage_reports_root_lim(r, n,
                                              DNA_V2_STORAGE_BITMAP_CAP,
                                              out);
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

/* HF-7 P1c-1 (snapshot design §8.9 S5; contract: nodus_witness_v2_
 * storage.h). The SAME scan as the v1 root above (st_segments_load: typed
 * columns, k and published_height each 1..INT64_MAX, k exactly 1..n), so
 * the two can never disagree on which rows are well-formed; only the leaf
 * gains published_height. */
int nodus_witness_storage_segments_root_v2(nodus_witness_t *w,
                                           uint8_t out[64]) {
    if (!w || !w->db || !out) return -1;
    st_seg_t *s = NULL;
    size_t n = 0;
    if (st_segments_load(w, UINT64_MAX, &s, &n) != 0) return -1;
    uint64_t *ks = n ? malloc(n * sizeof(*ks)) : NULL;
    uint64_t *phs = n ? malloc(n * sizeof(*phs)) : NULL;
    uint8_t (*rs)[64] = n ? malloc(n * sizeof(*rs)) : NULL;
    int ret = -1;
    if (n == 0 || (ks && phs && rs)) {
        for (size_t i = 0; i < n; i++) {
            ks[i] = s[i].k;
            phs[i] = s[i].published_height;
            memcpy(rs[i], s[i].root, 64);
        }
        ret = dna_v2_segments_root_v2(ks, (const uint8_t (*)[64])rs, phs,
                                      n, out);
    }
    free(rs);
    free(phs);
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

/* ── the grace rule and the eligibility rule (header "GRACE" and
 *    "ELIGIBILITY") ─────────────────────────────────────────────────── */

int nodus_storage_grace_next(uint64_t prev, uint64_t H, uint64_t n,
                             uint64_t E, uint64_t *out) {
    if (!out) return -1;
    if (n == 0) { *out = prev; return 0; }
    uint64_t span = 0, g = 0;
    if (dna_ck_mul_u64(n, E, &span) != 0 ||
        dna_ck_add_u64(H, span, &g) != 0)
        return -1;                        /* H + n·E past u64: a fault   */
    *out = g > prev ? g : prev;
    return 0;
}

int nodus_storage_grace_counts(uint64_t H, uint64_t E,
                               uint64_t published_height, int prev_exists,
                               int in_cur, int in_prev) {
    if (!prev_exists || H < E) return 0;  /* first storage boundary     */
    if (published_height > H - E) return 0;   /* new since H−E (K9a)    */
    return (in_cur && !in_prev) ? 1 : 0;      /* taken over             */
}

int nodus_storage_in_grace(uint64_t H, uint64_t grace_until) {
    return H < grace_until ? 1 : 0;
}

int nodus_storage_member_eligible(uint64_t H, uint64_t grace_until,
                                  int in_cur, int in_prev) {
    if (nodus_storage_in_grace(H, grace_until)) return 0;
    return (in_cur || in_prev) ? 1 : 0;
}

/* The member ↔ segment relation of epoch (H, H+E] — the ONE walk every
 * consumer reads (the grace count at the freeze, the settlement weights,
 * the probe's eligible list). For each published segment k (k ascending)
 * of `segs` (published_height <= H) and each member m of `cur` =
 * storage_set(H):
 *     in_cur  = m ∈ holders(k, set(H))
 *     in_prev = published_height(k) <= H − E  and  m ∈ holders(k, set(H−E))
 * `rel(ud, m, k, published_height(k), in_cur, in_prev)` is called once
 * per (m, k) with at least one of the two set; a holder of set(H−E) that
 * is not a member of set(H) has no index and is skipped (no bit, no
 * pay). `prev` = set(H−E), count 0 when absent. Within one member the
 * calls come in k ascending order. @return 0 / -1. */
typedef int (*st_rel_fn)(void *ud, size_t member, uint64_t k, uint64_t pub,
                         int in_cur, int in_prev);

static int st_member_walk(const nodus_storage_set_t *cur,
                          const nodus_storage_set_t *prev, uint64_t H,
                          const st_seg_t *segs, size_t n_segs,
                          st_rel_fn rel, void *ud) {
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    if (cur->count == 0) return 0;
    if (H < E) return -1;                 /* H is a positive multiple of E */
    for (size_t s = 0; s < n_segs; s++) {
        if (segs[s].published_height > H) return -1;   /* caller's bound */
        uint8_t hc[DNA_V2_STORAGE_HOLDERS][64], hp[DNA_V2_STORAGE_HOLDERS][64];
        size_t nc = 0, np = 0;
        if (nodus_witness_storage_holders(cur, segs[s].root, hc, &nc) != 0)
            return -1;
        if (prev->count > 0 && segs[s].published_height <= H - E &&
            nodus_witness_storage_holders(prev, segs[s].root, hp, &np) != 0)
            return -1;
        /* the (at most 2R) members involved, each once, with both flags */
        size_t m_of[2 * DNA_V2_STORAGE_HOLDERS];
        int fc[2 * DNA_V2_STORAGE_HOLDERS], fpv[2 * DNA_V2_STORAGE_HOLDERS];
        size_t nm = 0;
        for (size_t j = 0; j < nc + np; j++) {
            const int from_cur = j < nc;
            long m = st_find_fp((const uint8_t (*)[64])cur->fps, cur->count,
                                from_cur ? hc[j] : hp[j - nc]);
            if (m < 0) {
                if (from_cur) return -1;  /* a holder of set(H) is in it */
                continue;                 /* left the set: no bit, no pay */
            }
            size_t q = 0;
            while (q < nm && m_of[q] != (size_t)m) q++;
            if (q == nm) { m_of[nm] = (size_t)m; fc[nm] = 0; fpv[nm] = 0;
                           nm++; }
            if (from_cur) fc[q] = 1;
            else fpv[q] = 1;
        }
        for (size_t q = 0; q < nm; q++)
            if (rel(ud, m_of[q], segs[s].k, segs[s].published_height, fc[q],
                    fpv[q]) != 0)
                return -1;
    }
    return 0;
}

/* Settlement weights: P blocks per ELIGIBLE segment (K1). */
typedef struct {
    const nodus_storage_set_t *cur;
    uint64_t H;
    uint64_t weight[DNA_V2_STORAGE_SET_CAP];   /* capacity; count <= the
                                                * set's generation limit */
} st_weights_t;

static int st_rel_weight(void *ud, size_t member, uint64_t k, uint64_t pub,
                         int in_cur, int in_prev) {
    (void)k;
    (void)pub;
    st_weights_t *wt = ud;
    if (!nodus_storage_member_eligible(wt->H, wt->cur->grace_until[member],
                                       in_cur, in_prev))
        return 0;
    return dna_ck_add_u64(wt->weight[member], ST_P, &wt->weight[member]) == 0
               ? 0 : -1;
}

/* One member's ELIGIBLE segments, k ascending. */
typedef struct {
    const nodus_storage_set_t *cur;
    uint64_t  H;
    size_t    target;
    uint64_t *ks;
    size_t    cap, n;
} st_collect_t;

static int st_rel_collect(void *ud, size_t member, uint64_t k, uint64_t pub,
                          int in_cur, int in_prev) {
    (void)pub;
    st_collect_t *c = ud;
    if (member != c->target) return 0;
    if (!nodus_storage_member_eligible(c->H, c->cur->grace_until[member],
                                       in_cur, in_prev))
        return 0;
    if (c->n < c->cap && c->ks) c->ks[c->n] = k;
    c->n++;
    return 0;
}

/* The freeze's grace count (K9a): n(m) = segments published at or before
 * H − E that m holds at H and did not hold at H − E; 0 for everyone when
 * set(H−E) does not exist. Each (m, k) through nodus_storage_grace_counts
 * (a segment published in (H−E, H] is not counted). */
typedef struct {
    uint64_t H;
    int      prev_exists;
    uint64_t n_new[DNA_V2_STORAGE_SET_CAP];
} st_newcount_t;

static int st_rel_new(void *ud, size_t member, uint64_t k, uint64_t pub,
                      int in_cur, int in_prev) {
    (void)k;
    st_newcount_t *nc = ud;
    if (!nodus_storage_grace_counts(nc->H, (uint64_t)DNAC_EPOCH_LENGTH, pub,
                                    nc->prev_exists, in_cur, in_prev))
        return 0;
    nc->n_new[member]++;                  /* <= the segment count: no wrap */
    return 0;
}

/* ── the generation-6 relation of one member (HF-9 plan §8.4, §8.5): the
 *    segments m holds in epoch (H, H+E] = the rows of m active at H (the
 *    current relation) UNION the rows active at H - E (the previous one),
 *    ascending, no duplicates. At H = B1 the previous relation is
 *    XOR(set(H - E)) over the segments published at or before H - E
 *    (§8.6, node-locally); for H - E >= B1 it is the rows. ──────────────── */

/* The k's of fp's rows active at X, ascending, appended after *n. */
static int st_ks_rows_at(nodus_witness_t *w, const uint8_t fp[64],
                         uint64_t X, uint64_t **arr, size_t *n,
                         size_t *cap) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT k FROM v2_storage_assign WHERE node_fp = ?1 AND "
            "from_h <= ?2 AND (to_h IS NULL OR to_h > ?2) ORDER BY k ASC",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, fp, 64, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)X);
    int rc, bad = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        sqlite3_int64 k = 0;
        if (!col_int(st, 0, 1, INT64_MAX, &k)) { bad = 1; break; }
        if (*n == *cap) {
            size_t nc = *cap ? *cap * 2 : 16;
            uint64_t *na = realloc(*arr, nc * sizeof(**arr));
            if (!na) { bad = 1; break; }
            *arr = na;
            *cap = nc;
        }
        (*arr)[(*n)++] = (uint64_t)k;
        g_nodus_storage_work.assign_rows_read++;
    }
    sqlite3_finalize(st);
    return (bad || rc != SQLITE_DONE) ? -1 : 0;
}

/* The k's m holds under XOR(set(X)), segments published <= X, ascending. */
static int st_ks_xor_at(nodus_witness_t *w, const uint8_t fp[64], uint64_t X,
                        uint64_t **arr, size_t *n, size_t *cap) {
    nodus_storage_set_t *set = calloc(1, sizeof(*set));
    st_seg_t *segs = NULL;
    size_t n_segs = 0;
    int ret = -1;
    if (!set) return -1;
    int rc = nodus_witness_storage_set_get(w, X, set);
    if (rc == 1) { ret = 0; goto done; }              /* no set: nothing  */
    if (rc != 0) goto done;
    if (st_segments_load(w, X, &segs, &n_segs) != 0) goto done;
    for (size_t s = 0; s < n_segs; s++) {
        uint8_t hf[DNA_V2_STORAGE_HOLDERS][64];
        size_t nh = 0;
        if (set->count == 0) break;
        if (nodus_witness_storage_holders(set, segs[s].root, hf, &nh) != 0)
            goto done;
        for (size_t j = 0; j < nh; j++)
            if (memcmp(hf[j], fp, 64) == 0) {
                if (*n == *cap) {
                    size_t nc = *cap ? *cap * 2 : 16;
                    uint64_t *na = realloc(*arr, nc * sizeof(**arr));
                    if (!na) goto done;
                    *arr = na;
                    *cap = nc;
                }
                (*arr)[(*n)++] = segs[s].k;
            }
    }
    ret = 0;
done:
    free(segs);
    free(set);
    return ret;
}

int nodus_witness_storage_member_ks(nodus_witness_t *w, uint64_t H,
                                    const uint8_t fp[64], uint64_t **ks_out,
                                    size_t *n_out) {
    if (!w || !w->db || !fp || !ks_out || !n_out) return -1;
    *ks_out = NULL;
    *n_out = 0;
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    if (H == 0 || (H % E) != 0) return -1;
    if (nodus_witness_storage_gen6_at(w, H) != 1) return -1;  /* not gen 6 */
    uint64_t *a = NULL, *b = NULL, *u = NULL;
    size_t na = 0, ca = 0, nb = 0, cb = 0, nu = 0;
    int ret = -1;
    if (st_ks_rows_at(w, fp, H, &a, &na, &ca) != 0) goto done;
    if (H > E) {
        const uint64_t X = H - E;
        int g = nodus_witness_storage_gen6_at(w, X);
        if (g < 0) goto done;
        if ((g ? st_ks_rows_at(w, fp, X, &b, &nb, &cb)
               : st_ks_xor_at(w, fp, X, &b, &nb, &cb)) != 0)
            goto done;
    }
    u = malloc((na + nb + 1) * sizeof(*u));
    if (!u) goto done;
    {
        size_t i = 0, j = 0;
        while (i < na || j < nb) {
            uint64_t v;
            if (j == nb || (i < na && a[i] <= b[j])) {
                v = a[i++];
                if (j < nb && b[j] == v) j++;
            } else {
                v = b[j++];
            }
            if (nu > 0 && u[nu - 1] >= v) goto done;   /* not ascending   */
            u[nu++] = v;
        }
    }
    *ks_out = u;
    *n_out = nu;
    u = NULL;
    ret = 0;
done:
    free(u);
    free(b);
    free(a);
    return ret;
}

int nodus_witness_storage_holders_at(nodus_witness_t *w, uint64_t k,
                                     const uint8_t seg_root[64], uint64_t X,
                                     uint8_t out_fps[DNA_V2_STORAGE_HOLDERS_CAP][64],
                                     size_t *n_out) {
    if (!w || !w->db || !seg_root || !out_fps || !n_out) return -1;
    *n_out = 0;
    int g = nodus_witness_storage_gen6_at(w, X);
    if (g < 0) return -1;
    if (g) {
        /* the rows of k active at X: from_h <= X < to_h (or current) */
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT node_fp FROM v2_storage_assign WHERE k = ?1 AND "
                "from_h <= ?2 AND (to_h IS NULL OR to_h > ?2) "
                "ORDER BY node_fp ASC", -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)k);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)X);
        size_t n = 0;
        int rc, bad = 0;
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            if (n >= ST_R_CAP || !col_blob_len(st, 0, 64)) { bad = 1; break; }
            memcpy(out_fps[n++], sqlite3_column_blob(st, 0), 64);
        }
        sqlite3_finalize(st);
        if (bad || rc != SQLITE_DONE) return -1;
        *n_out = n;
        return 0;
    }
    nodus_storage_set_t *set = calloc(1, sizeof(*set));
    if (!set) return -1;
    int rc = nodus_witness_storage_set_get(w, X, set);
    int ret = -1;
    if (rc == 0) {
        uint8_t hf[DNA_V2_STORAGE_HOLDERS][64];
        size_t nh = 0;
        if (set->count == 0 ||
            nodus_witness_storage_holders(set, seg_root, hf, &nh) == 0) {
            for (size_t i = 0; i < nh; i++) memcpy(out_fps[i], hf[i], 64);
            *n_out = nh;
            ret = 0;
        }
    }
    free(set);
    return ret;
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
    /* in grace: nothing is eligible (the walk below would say the same) */
    if (nodus_storage_in_grace(epoch_start, cur->grace_until[me])) {
        ret = 0;
        goto done;
    }
    {
        /* from generation 6 (H >= B1) the relation is the member's own
         * assignment rows (O(own rows), plan §8.8), not a segment walk */
        const int g6 = nodus_witness_storage_gen6_at(w, epoch_start);
        if (g6 < 0) goto done;
        if (g6) {
            uint64_t *all = NULL;
            size_t na = 0;
            if (nodus_witness_storage_member_ks(w, epoch_start, node_fp,
                                                &all, &na) != 0)
                goto done;
            for (size_t i = 0; i < na && i < cap; i++) ks_out[i] = all[i];
            free(all);
            *n_out = na;
            ret = na <= cap ? 0 : -1;
            goto done;
        }
    }
    if (st_segments_load(w, epoch_start, &segs, &n_segs) != 0)
        goto done;
    st_collect_t c = { cur, epoch_start, (size_t)me, ks_out, cap, 0 };
    if (st_member_walk(cur, prev, epoch_start, segs, n_segs, st_rel_collect,
                       &c) != 0)
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
    if (had_eligible && ok) return 0u;               /* K5a: even at ≥ 3  */
    if (old >= DNA_V2_STORAGE_FAIL_LIMIT) {          /* skipped (K5)      */
        if (old >= NODUS_STORAGE_FAIL_RETURN - 1u) return 0u;
        return old + 1u;
    }
    if (!had_eligible) return old;
    return old + 1u;                                 /* weight, NOT OK    */
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

int nodus_storage_member_verdict(uint32_t n_seat, const uint64_t *power,
                                 const uint8_t (*seat_owner)[64],
                                 const uint8_t (*seat_key)[64],
                                 const uint8_t *reported, const uint8_t *bit,
                                 uint64_t p_total,
                                 const uint8_t member_owner[64],
                                 const uint8_t member_fp[64],
                                 nodus_storage_verdict_t *out,
                                 uint64_t *i_out, uint64_t *y_out) {
    if ((n_seat > 0 && (!power || !seat_owner || !seat_key || !reported ||
                        !bit)) ||
        !member_owner || !member_fp || !out)
        return -1;
    uint64_t I = 0, Y = 0;
    for (uint32_t s = 0; s < n_seat; s++) {             /* seat order */
        if (!reported[s]) continue;
        /* F2, kural (a) (design rev 6 §11.6; K16 item 8): a report from
         * the member's own owner OR from the member's own key does not
         * count for or against it */
        if (memcmp(seat_owner[s], member_owner, 64) == 0 ||
            memcmp(seat_key[s], member_fp, 64) == 0)
            continue;
        if (dna_ck_add_u64(I, power[s], &I) != 0) return -1;
        if (bit[s] && dna_ck_add_u64(Y, power[s], &Y) != 0) return -1;
    }
    /* design rev 6 §11.6 (K16 item 8): "2·I_m ≤ P_toplam → KANIT YOK;
     * aksi hâlde 3·Y_m > 2·I_m → OK, değilse OK DEĞİL" — `<=` at the
     * floor: the exact split 2·I == P_total is NO_EVIDENCE */
    uint64_t i2 = 0, y3 = 0;
    if (dna_ck_mul_u64(I, 2, &i2) != 0 || dna_ck_mul_u64(Y, 3, &y3) != 0)
        return -1;
    if (i2 <= p_total)  *out = NODUS_STORAGE_NO_EVIDENCE;
    else if (y3 > i2)   *out = NODUS_STORAGE_OK;
    else                *out = NODUS_STORAGE_NOT_OK;
    if (i_out) *i_out = I;
    if (y_out) *y_out = Y;
    return 0;
}

int nodus_witness_storage_seat_owners(nodus_witness_t *w,
                                      const dna_vset_snapshot_t *snap,
                                      const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                                      uint8_t (*owner_out)[64]) {
    if (!snap || !owner_out) return -1;
    if (snap->selection_ruleset == DNA_VSET_RULESET_TOPN_V2) {
        for (uint32_t s = 0; s < snap->active_count; s++)
            memcpy(owner_out[s], snap->entries[s].owner_fp, 64);
        return 0;
    }
    if (snap->selection_ruleset != DNA_VSET_RULESET_TOPN_V1) {
        QGP_LOG_ERROR(LOG_TAG, "storage settlement: snapshot ruleset %u "
                      "has no owner rule — refusing",
                      (unsigned)snap->selection_ruleset);
        return -1;
    }
    /* RULESET 1 — the §7.5 bridge (design rev 6 §11.7: "pubkey →
     * validator_id → commit edilmiş satırın owner_fp'si; satırlar
     * silinmez"), the read the distribution's v2ec_member_load makes; a
     * row it cannot find is a FAULT here (khan A1, 2026-10-12) */
    if (!w || !w->db || !chain_id) return -1;
    nodus_v2_validator_row_t *row = calloc(1, sizeof(*row));
    if (!row) return -1;
    int ret = -1;
    for (uint32_t s = 0; s < snap->active_count; s++) {
        uint8_t vid[NODUS_V2_VALIDATOR_ID_LEN];
        if (dna_validator_id_migrated(vid, chain_id,
                                      snap->entries[s].pubkey) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "storage settlement: seat %u's migrated "
                          "validator_id did not derive", (unsigned)s);
            goto done;
        }
        const int rc = nodus_validator_v2_get(w, vid, row);
        if (rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "storage settlement: seat %u of a "
                          "ruleset-1 snapshot — the validator row keyed by "
                          "its migrated id is %s (rows are never deleted: "
                          "corrupt state)", (unsigned)s,
                          rc == 1 ? "absent" : "unreadable or malformed");
            goto done;
        }
        memcpy(owner_out[s], row->owner_fp, 64);
    }
    ret = 0;
done:
    free(row);
    return ret;
}

/* STEP 1 — settle epoch (H, H+E], H = B − 2E. `chain_id` = the boundary's
 * (nodus_witness_storage_boundary_apply's — the migration's own input),
 * read only by the ruleset-1 owner bridge. @return 0 / -2. */
static int st_settle(nodus_witness_t *w, uint64_t B,
                     const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                     int gen6, nodus_storage_boundary_t *out) {
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
    uint8_t (*seat_owner)[64] = NULL;
    uint8_t *reported = NULL, *bit = NULL;
    const dna_v2_storage_report_t **by_seat = NULL;
    if (!cur || !prev || !wt) goto done;

    int rc = nodus_witness_storage_set_get(w, H, cur);
    if (rc == 1) { ret = 0; goto done; }  /* no set(H): first boundaries */
    if (rc != 0) goto done;
    rc = nodus_witness_storage_set_get(w, H - E, prev);
    if (rc < 0) goto done;
    if (rc == 1) prev->count = 0;         /* no set(H−E): nothing held
                                           * before H, no overlap; nobody
                                           * got grace at H (K9a)        */

    /* ── weights (K1 block count; the eligibility rule, header) ───── */
    wt->cur = cur;
    wt->H = H;
    if (gen6) {
        /* HF-9 §8.5 "Settlement at B for H = B - 2E": weight(m) = P x
         * held_union(m, H) unless m is in grace at H. The union count was
         * written at boundary H (or, for the two epochs settled at B1 and
         * B1 + E, by the edge's E-s1). A set member WITHOUT a row is
         * missing derived data: a FAULT, never weight 0 (§8.4). */
        for (uint32_t i = 0; i < cur->count; i++) {
            uint64_t hu = 0, nn = 0;
            int mr = st_member_epoch_get(w, H, cur->fps[i], &hu, &nn);
            if (mr != 0) {
                QGP_LOG_ERROR(LOG_TAG, "settlement at %llu: member %u of "
                              "storage_set(%llu) has no v2_storage_member_"
                              "epoch row (%s) - derived data missing",
                              (unsigned long long)B, (unsigned)i,
                              (unsigned long long)H,
                              mr == 1 ? "absent" : "unreadable");
                goto done;
            }
            if (nodus_storage_in_grace(H, cur->grace_until[i])) continue;
            if (dna_ck_mul_u64(hu, ST_P, &wt->weight[i]) != 0) goto done;
        }
    } else {
        if (st_segments_load(w, H, &segs, &n_segs) != 0) goto done;
        if (st_member_walk(cur, prev, H, segs, n_segs, st_rel_weight, wt)
            != 0)
            goto done;
    }
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
    seat_owner = calloc(n_seat, sizeof(*seat_owner));
    reported = calloc(n_seat, sizeof(*reported));
    bit = calloc(n_seat, sizeof(*bit));
    by_seat = calloc(n_seat, sizeof(*by_seat));
    if (!power || !seat_fp || !seat_owner || !reported || !bit || !by_seat)
        goto done;
    /* HF-6 slice 5b (ORCHESTRATOR decision D3; design rev 6 §5 consumer
     * list, §11.7): the seats' power from THE ONE helper, computed once
     * over the whole snapshot (ruleset 1: total / DNAC_DECIMAL_UNIT as
     * before; ruleset 2: the counted power at that snapshot's epoch
     * ratio) — never re-capped over the subset a member's exclusion
     * leaves (§11.6). A power that cannot be computed is a FAULT. */
    if (nodus_witness_vset_powers(w, snap, power) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "settlement at %llu: snapshot(%llu)'s voting "
                      "power cannot be computed", (unsigned long long)B,
                      (unsigned long long)H);
        goto done;
    }
    uint64_t P_total = 0;
    for (uint32_t s = 0; s < n_seat; s++) {
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
        reported[rp->seat] = 1u;
        if (dna_ck_add_u64(P_rep, power[rp->seat], &P_rep) != 0) goto done;
    }

    /* ── F1: reports from MORE THAN 1/2 of total power, else nothing
     *    moves for that epoch (no pay, no fail_streak). Kept BEFORE any
     *    registry row or owner is read: an F1-failed epoch returns 0
     *    here exactly as before HF-6 6b-2 ──────────────────────────── */
    {
        uint64_t twice = 0;
        if (dna_ck_mul_u64(P_rep, 2, &twice) != 0) goto done;
        if (!(twice > P_total)) { ret = 0; goto done; }
    }
    out->settled = 1;

    /* ── the registry rows of the members (owner, live fail_streak) —
     *    read BEFORE the verdicts: the exclusion compares each member's
     *    owner (HF-6 6b-2) ─────────────────────────────────────────── */
    long row_of[DNA_V2_STORAGE_SET_CAP];
    if (gen6) {
        /* HF-9 §8.5/§8.8: the members' registry rows by node_fp (<= cap
         * point reads), not the whole registry (RELEASED rows included) */
        rows = calloc(cur->count ? cur->count : 1, sizeof(*rows));
        if (!rows) goto done;
        n_rows = cur->count;
        for (uint32_t i = 0; i < cur->count; i++) {
            int gr = nodus_witness_storage_registry_get(w, cur->fps[i],
                                                        &rows[i]);
            g_nodus_storage_work.registry_rows_read++;
            if (gr != 0) {
                QGP_LOG_ERROR(LOG_TAG, "settlement at %llu: a member of "
                              "storage_set(%llu) has no readable registry "
                              "row", (unsigned long long)B,
                              (unsigned long long)H);
                goto done;
            }
        }
    } else if (nodus_witness_storage_registry_load(w, &rows, &n_rows) != 0) {
        goto done;
    }
    for (uint32_t i = 0; i < cur->count; i++) {
        row_of[i] = gen6 ? (long)i : st_find_row(rows, n_rows, cur->fps[i]);
        if (row_of[i] < 0) {              /* registry rows never vanish */
            QGP_LOG_ERROR(LOG_TAG, "settlement at %llu: a member of "
                          "storage_set(%llu) has no registry row",
                          (unsigned long long)B, (unsigned long long)H);
            goto done;
        }
    }

    /* ── the seats' keys must be distinct (two seats, one key: corrupt
     *    — the exclusion's key clause would otherwise be ambiguous), and
     *    owner(s) once per settlement (header "SETTLEMENT": ruleset 2
     *    the entry's owner_fp; ruleset 1 the §7.5 bridge, khan A1: a
     *    missing row is a FAULT). The step-0 gate proved generation >=
     *    NODUS_RT_GEN_STORAGE, so a ruleset-1 snapshot here IS the first
     *    settlement after the generation-4 edge. Not read for an empty
     *    set: nothing would consume it ───────────────────────────────── */
    for (uint32_t s = 0; s < n_seat; s++)
        for (uint32_t t = s + 1; t < n_seat; t++)
            if (memcmp(seat_fp[s], seat_fp[t], 64) == 0) {
                QGP_LOG_ERROR(LOG_TAG, "settlement at %llu: seats %u and %u "
                              "of snapshot(%llu) carry one key — corrupt",
                              (unsigned long long)B, (unsigned)s,
                              (unsigned)t, (unsigned long long)H);
                goto done;
            }
    if (cur->count > 0 &&
        nodus_witness_storage_seat_owners(w, snap, chain_id, seat_owner)
            != 0) {
        QGP_LOG_ERROR(LOG_TAG, "settlement at %llu: the owners of "
                      "snapshot(%llu)'s seats cannot be read",
                      (unsigned long long)B, (unsigned long long)H);
        goto done;
    }

    /* ── per-member verdict: the owner-OR-key exclusion and the three
     *    states (header "SETTLEMENT"; nodus_storage_member_verdict:
     *    2·I <= P_total → NO_EVIDENCE, else 3·Y > 2·I → OK, else
     *    NOT_OK — design rev 6 §11.6) ──────────────────────────────── */
    nodus_storage_verdict_t verdict[DNA_V2_STORAGE_SET_CAP];
    for (uint32_t i = 0; i < cur->count; i++) {
        for (uint32_t s = 0; s < n_seat; s++)
            bit[s] = by_seat[s] ? (uint8_t)((by_seat[s]->bitmap[i / 8u] >>
                                             (i % 8u)) & 1u)
                                : 0u;
        if (nodus_storage_member_verdict(
                n_seat, power, (const uint8_t (*)[64])seat_owner,
                (const uint8_t (*)[64])seat_fp, reported, bit, P_total,
                rows[row_of[i]].payee_fp, cur->fps[i], &verdict[i], NULL,
                NULL) != 0)
            goto done;
    }

    /* ── weighted pay from pool 1 (W == 0 → nothing) — OK members only,
     *    to the row's OWNER (the payee_fp column since 6b-1); W keeps
     *    every member's weight, NO_EVIDENCE included ───────────────── */
    if (W > 0) {
        uint64_t pool1 = 0;
        if (st_pool1_get(w, &pool1) != 0) goto done;
        const uint64_t budget = pool1 >> NODUS_V2_GEN_REWARD_DIVISOR_LOG2;
        uint64_t total = 0;
        for (uint32_t i = 0; i < cur->count && budget > 0; i++) {
            if (verdict[i] != NODUS_STORAGE_OK || wt->weight[i] == 0)
                continue;
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

    /* ── fail_streak (bytes item 4 + K5 + K5a) — an eligible block and
     *    OK resets to 0 whatever the old value; else at 3 or more every
     *    member adds one (14 + 1 written as 0); else below 3 an eligible
     *    block and NOT OK adds one, no eligible block leaves it. A member
     *    in grace for (H, H+E] (K9) is left unchanged, whatever its value
     *    — the K9 text "fail_streak unchanged" (header "SETTLEMENT"); a
     *    NO_EVIDENCE member the same way, also at 3 or more (design rev 6
     *    §11.6 "hata sayacı DEĞİŞMEZ") ──────────────────────────────── */
    for (uint32_t i = 0; i < cur->count; i++) {
        if (nodus_storage_in_grace(H, cur->grace_until[i])) continue;
        if (verdict[i] == NODUS_STORAGE_NO_EVIDENCE) continue;
        const uint32_t old = rows[row_of[i]].fail_streak;
        const uint32_t nv = nodus_storage_fail_streak_next(
                                old, wt->weight[i] > 0,
                                verdict[i] == NODUS_STORAGE_OK);
        if (st_streak_write(w, cur->fps[i], old, nv) != 0) goto done;
    }
    ret = 0;

done:
    free(rows);
    free(by_seat);
    free(bit);
    free(reported);
    free(seat_owner);
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

/* STEP 2 — prune what the settlement just consumed (exported so the
 * pruning rule can be proven over synthetic rows, like publish_due and
 * freeze_gen6; the boundary calls this same code). @return 0 / -2. */
int nodus_witness_storage_prune(nodus_witness_t *w, uint64_t B, int gen6) {
    if (!w || !w->db) return -2;
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
    /* HF-9 §8.4: v2_storage_member_epoch is pruned with the set members
     * (same rule); the assignment rows are never pruned (D6) */
    if (gen6 && st_exec1(w, "DELETE FROM v2_storage_member_epoch WHERE "
                         "epoch_start < ?1", H) != 0)
        return -2;
    return 0;
}

/* STEP 3 — release every EXITING row (bytes 2026-10-04 item 6).
 * @return 0 / -2. */
static int st_release(nodus_witness_t *w, uint64_t B,
                      const uint8_t chain_id[DNA_CHAIN_ID_LEN], int gen6,
                      nodus_storage_boundary_t *out) {
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    uint64_t lock = 0, unlock = 0;
    if (dna_ck_mul_u64((uint64_t)DNAC_STORAGE_EXIT_LOCK_EPOCHS, E, &lock)
            != 0 ||
        dna_ck_add_u64(B, lock, &unlock) != 0 || unlock > ST_STORE_MAX)
        return -2;
    dna_v2_storage_node_row_t *rows = NULL;
    size_t n = 0;
    /* HF-9 §8.8: from generation 6 only the EXITING rows are read (the
     * status index), not the whole registry */
    if (gen6 ? nodus_witness_storage_registry_load_status(
                   w, DNA_V2_STORAGE_EXITING, &rows, &n) != 0
             : nodus_witness_storage_registry_load(w, &rows, &n) != 0)
        return -2;
    g_nodus_storage_work.registry_rows_read += gen6 ? n : 0;
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
static int st_publish(nodus_witness_t *w, uint64_t B, int gen6,
                      nodus_storage_boundary_t *out) {
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    uint64_t delay = 0;
    if (dna_ck_mul_u64((uint64_t)DNAC_STORAGE_SEGMENT_DELAY_EPOCHS, E,
                       &delay) != 0)
        return -2;
    sqlite3_stmt *st = NULL;
    /* HF-9 §8.8: from generation 6 the contiguity COUNT(*) scan is not
     * kept - MAX(k) on the primary key; contiguity is inductive (this is
     * the only writer and it inserts max + 1; a broken table only harms
     * the node that holds it, decision D27). Generation <= 5 keeps the
     * COUNT(*) check unchanged. */
    if (sqlite3_prepare_v2(w->db, gen6
            ? "SELECT COALESCE(MAX(k), 0) FROM v2_storage_segments"
            : "SELECT COUNT(*), COALESCE(MAX(k), 0) "
              "FROM v2_storage_segments", -1, &st, NULL)
        != SQLITE_OK)
        return -2;
    int rc = sqlite3_step(st);
    /* generation 6: column 0 IS MAX(k) and the contiguity compare is not
     * made; generation <= 5: column 0 is COUNT(*), column 1 MAX(k) */
    sqlite3_int64 cnt = rc == SQLITE_ROW ? sqlite3_column_int64(st, 0) : -1;
    sqlite3_int64 mx = rc == SQLITE_ROW
                           ? sqlite3_column_int64(st, gen6 ? 0 : 1) : -1;
    sqlite3_finalize(st);
    if (cnt < 0 || (!gen6 && mx != cnt)) { /* 1..max, contiguous (<= 5)   */
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
    /* the exported backfill entry keeps the generation <= 5 form (the
     * COUNT(*) contiguity check) */
    if (st_publish(w, boundary_height, 0, &sb) != 0) return -1;
    *n_out = sb.n_published;
    return 0;
}

/* grace_until := nv, bound to the observed value. */
static int st_grace_write(nodus_witness_t *w, const uint8_t fp[64],
                          uint64_t old, uint64_t nv) {
    if (old == nv) return 0;
    if (old > ST_STORE_MAX || nv > ST_STORE_MAX) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "UPDATE v2_storage_nodes SET grace_until = ?1 "
            "WHERE node_fp = ?2 AND grace_until = ?3", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)nv);
    sqlite3_bind_blob(st, 2, fp, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)old);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return (rc == SQLITE_DONE && sqlite3_changes(w->db) == 1) ? 0 : -1;
}

/* STEP 5a — the K9 grace update over the set being frozen, counted per
 * K9a (header "GRACE"): for each member m of `set` = storage_set(B),
 * n(m) = the segments published at or before B − E that m holds in
 * set(B) and did not hold in set(B−E) — 0 for everyone when set(B−E)
 * does not exist (the first storage boundary); a segment published in
 * (B−E, B], the one STEP 4 published at B included, is not counted.
 * n > 0 → grace_until = max(grace_until, B + n·E) (checked; past the
 * stored INTEGER bound = fault), written to the registry row AND to
 * set->grace_until (the frozen copy). @return 0 / -2. */
static int st_grace_update(nodus_witness_t *w, uint64_t B,
                           nodus_storage_set_t *set) {
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    if (set->count == 0) return 0;
    int ret = -2;
    nodus_storage_set_t *prev = calloc(1, sizeof(*prev));
    st_newcount_t *nc = calloc(1, sizeof(*nc));
    st_seg_t *segs = NULL;
    size_t n_segs = 0;
    if (!prev || !nc) goto done;
    int rc = B > E ? nodus_witness_storage_set_get(w, B - E, prev) : 1;
    if (rc < 0) goto done;
    if (rc == 1) prev->count = 0;         /* nothing held before B       */
    nc->H = B;
    nc->prev_exists = rc == 0;            /* an empty frozen set counts  */
    if (st_segments_load(w, B, &segs, &n_segs) != 0) goto done;
    if (st_member_walk(set, prev, B, segs, n_segs, st_rel_new, nc) != 0)
        goto done;
    for (uint32_t i = 0; i < set->count; i++) {   /* node_fp ASC */
        const uint64_t old = set->grace_until[i];
        uint64_t nv = 0;
        if (nodus_storage_grace_next(old, B, nc->n_new[i], E, &nv) != 0 ||
            nv > ST_STORE_MAX) {
            QGP_LOG_ERROR(LOG_TAG, "storage boundary %llu: grace_until "
                          "overflow (%llu new segments)",
                          (unsigned long long)B,
                          (unsigned long long)nc->n_new[i]);
            goto done;
        }
        if (st_grace_write(w, set->fps[i], old, nv) != 0) goto done;
        set->grace_until[i] = nv;
    }
    ret = 0;
done:
    free(segs);
    free(nc);
    free(prev);
    return ret;
}

/* The set header row and its member rows of storage_set(B) (shared by the
 * generation <= 5 and the generation-6 freeze). @return 0 / -1. */
static int st_set_write(nodus_witness_t *w, uint64_t B,
                        const nodus_storage_set_t *set) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_storage_sets (epoch_start, set_hash, "
            "member_count) VALUES (?1, ?2, ?3)", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)B);
    sqlite3_bind_blob(st, 2, set->set_hash, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)set->count);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;        /* an existing set(B): fault */
    for (uint32_t i = 0; i < set->count; i++) {
        st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO v2_storage_set_members (epoch_start, node_fp, "
                "fail_streak, grace_until) VALUES (?1, ?2, ?3, ?4)", -1, &st,
                NULL)
            != SQLITE_OK)
            return -1;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)B);
        sqlite3_bind_blob(st, 2, set->fps[i], 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)set->fail_streak[i]);
        sqlite3_bind_int64(st, 4, (sqlite3_int64)set->grace_until[i]);
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) return -1;
    }
    return 0;
}

/* STEP 5 — freeze storage_set(B), with the K9 grace update (5a) applied
 * before the member rows are written. @return 0 / -2. */
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
        set->grace_until[set->count] = rows[i].grace_until;
        set->count++;
    }
    if (dna_v2_storage_set_hash(B, (const uint8_t (*)[64])set->fps,
                                set->count, set->set_hash) != 0)
        goto done;
    if (st_grace_update(w, B, set) != 0) goto done;
    if (st_set_write(w, B, set) != 0) goto done;
    out->set_count = set->count;
    ret = 0;
done:
    free(set);
    free(rows);
    return ret;
}

/* ══════════════════════════════════════════════════════════════════════
 * HF-9 WP4 - the generation-6 assignment (plan §8.3-§8.6)
 * ════════════════════════════════════════════════════════════════════ */

/* The first `copies` of the n candidates in the rank order of
 * dna_v2_hrw_rank_cmp (the selector's ONE comparator), by insertion.
 * out_idx[0..*n_out) are indices into the candidate arrays. */
static void st_select_top(const uint8_t (*fp)[64], const uint8_t (*score)[64],
                          size_t n, size_t copies,
                          size_t out_idx[ST_R_CAP], size_t *n_out) {
    size_t nb = 0;
    for (size_t i = 0; i < n; i++) {
        size_t pos = nb;
        while (pos > 0 &&
               dna_v2_hrw_rank_cmp(score[i], fp[i], score[out_idx[pos - 1]],
                                   fp[out_idx[pos - 1]]) > 0)
            pos--;
        if (pos >= copies) continue;
        size_t last = nb < copies ? nb : copies - 1;
        for (size_t t = last; t > pos; t--) out_idx[t] = out_idx[t - 1];
        out_idx[pos] = i;
        if (nb < copies) nb++;
    }
    *n_out = nb;
}

/* Is fp in the list (linear; the lists here hold at most R entries)? */
static int st_in_list(const uint8_t (*list)[64], size_t n,
                      const uint8_t fp[64]) {
    for (size_t i = 0; i < n; i++)
        if (memcmp(list[i], fp, 64) == 0) return 1;
    return 0;
}

/* The assignment of boundary B (plan §8.5). `set` = the set being frozen
 * (ACTIVE rows, node_fp ASC, fail_streak as frozen); `R` = param 25 at B;
 * `n_pub` = the segments published at THIS boundary (the top n_pub of
 * v2_storage_segments). On success held_union[i] / n_new[i] (i = set
 * member index) hold the values written to v2_storage_member_epoch(B), and
 * the rows, `held`, the basis and the state are updated.
 *
 * Cases (the rule is stated once here):
 *  - EVENT = a departure from or an arrival in the eligible list against
 *    the basis, or R != the basis' R: every published segment is visited
 *    once (operator exception D11); rows(k) = the stored current rows,
 *    prev(k) = rows(k) - except at B1 (state.xfer = 1), where prev(k) =
 *    XOR(set(B - E)) (§8.6); new(k) = the first R eligible members in the
 *    rank order - by the join rule (the R stored rows with their stored
 *    scores + the arrivals' fresh scores, through the same comparator) when
 *    the segment existed at the previous boundary, no holder in rows(k)
 *    departed and R is unchanged, else by scoring every eligible member
 *    (dna_v2_segment_holders_hrw). A segment published at this boundary has
 *    no rows and no prev and is assigned in full.
 *  - NO EVENT: only the segments published at B are assigned
 *    (held_union = held; n_new = 0), except at B1 where the one-use
 *    XOR-vs-rendezvous table of E-s3 supplies ended_x / new_x.
 * Counts (K9a): only segments published at or before B - E, only members
 * of set(B). @return 0 / -2. */
static int st_assign_boundary(nodus_witness_t *w, uint64_t B,
                              const nodus_storage_set_t *set, uint32_t R,
                              uint32_t n_pub, uint64_t *held_union,
                              uint64_t *n_new) {
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    int ret = -2;
    uint8_t (*elig)[64]  = calloc(DNA_V2_STORAGE_SET_CAP, 64);
    uint8_t (*basis)[64] = calloc(DNA_V2_STORAGE_SET_CAP, 64);
    uint8_t (*dep)[64]   = calloc(DNA_V2_STORAGE_SET_CAP, 64);
    uint8_t (*arr)[64]   = calloc(DNA_V2_STORAGE_SET_CAP, 64);
    uint8_t (*cfp)[64]   = calloc(DNA_V2_STORAGE_SET_CAP + ST_R_CAP, 64);
    uint8_t (*csc)[64]   = calloc(DNA_V2_STORAGE_SET_CAP + ST_R_CAP, 64);
    uint64_t *ended      = calloc(DNA_V2_STORAGE_SET_CAP, sizeof(uint64_t));
    nodus_storage_set_t *prevset = NULL;
    sqlite3_stmt *seg = NULL;
    size_t n_elig = 0, n_basis = 0, n_dep = 0, n_arr = 0;
    if (!elig || !basis || !dep || !arr || !cfp || !csc || !ended) goto done;
    memset(held_union, 0, set->count * sizeof(*held_union));
    memset(n_new, 0, set->count * sizeof(*n_new));

    /* ── the state and the basis ─────────────────────────────────────── */
    int present = 0, xfer = 0;
    uint32_t copies_old = R;
    uint64_t b_old = 0;
    if (st_state_get(w, &present, &copies_old, &b_old, &xfer) != 0) goto done;
    if (!present) {
        /* no state at a generation-6 freeze: legitimate only as the very
         * first freeze (no set(B - E) exists); a chain with an earlier set
         * and no state lost its initialization - a FAULT (§8.4) */
        prevset = calloc(1, sizeof(*prevset));
        if (!prevset) goto done;
        int pr = B > E ? nodus_witness_storage_set_get(w, B - E, prevset) : 1;
        if (pr != 1) {
            QGP_LOG_ERROR(LOG_TAG, "storage boundary %llu: no assignment "
                          "state although storage_set(%llu) exists (%s) - "
                          "derived data missing",
                          (unsigned long long)B,
                          (unsigned long long)(B - E),
                          pr == 0 ? "frozen" : "unreadable");
            goto done;
        }
        copies_old = R;
        xfer = 0;
    } else {
        if (b_old + E != B) {
            QGP_LOG_ERROR(LOG_TAG, "storage boundary %llu: the assignment "
                          "state is at %llu, not the previous boundary - "
                          "derived data stale", (unsigned long long)B,
                          (unsigned long long)b_old);
            goto done;
        }
        if (st_basis_load(w, basis, DNA_V2_STORAGE_SET_CAP, &n_basis) != 0)
            goto done;
    }
    for (uint32_t i = 0; i < set->count; i++)
        if (set->fail_streak[i] < DNA_V2_STORAGE_FAIL_LIMIT)
            memcpy(elig[n_elig++], set->fps[i], 64);

    /* ── the diff against the basis, O(cap): both lists ascending ────── */
    {
        size_t a = 0, b = 0;
        while (a < n_basis || b < n_elig) {
            int c = a == n_basis ? 1 : b == n_elig ? -1
                    : memcmp(basis[a], elig[b], 64);
            if (c == 0) { a++; b++; }
            else if (c < 0) memcpy(dep[n_dep++], basis[a++], 64);
            else memcpy(arr[n_arr++], elig[b++], 64);
        }
    }
    const int event = n_dep > 0 || n_arr > 0 || copies_old != R;
    const int is_b1 = xfer;

    /* B1 with an event needs XOR(set(B - E)) per old segment */
    if (event && is_b1) {
        prevset = calloc(1, sizeof(*prevset));
        if (!prevset) goto done;
        /* xfer = 1 was written only when set(B - E) existed (E-s2); it is
         * pruned no earlier than B + E, so it must be there */
        if (nodus_witness_storage_set_get(w, B - E, prevset) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "storage boundary %llu: the previous "
                          "epoch's set is needed for the transition and "
                          "is missing", (unsigned long long)B);
            goto done;
        }
    }

    /* ── the segments to visit ───────────────────────────────────────── */
    uint64_t first_k = 1;
    if (!event) {
        if (n_pub == 0) goto no_segments;
        sqlite3_stmt *mx = NULL;
        if (sqlite3_prepare_v2(w->db, "SELECT COALESCE(MAX(k), 0) FROM "
                               "v2_storage_segments", -1, &mx, NULL)
            != SQLITE_OK)
            goto done;
        sqlite3_int64 top = sqlite3_step(mx) == SQLITE_ROW
                                ? sqlite3_column_int64(mx, 0) : -1;
        sqlite3_finalize(mx);
        if (top < (sqlite3_int64)n_pub) goto done;
        first_k = (uint64_t)top - n_pub + 1;
    }
    if (sqlite3_prepare_v2(w->db,
            "SELECT k, root, published_height FROM v2_storage_segments "
            "WHERE k >= ?1 ORDER BY k ASC", -1, &seg, NULL) != SQLITE_OK)
        goto done;
    sqlite3_bind_int64(seg, 1, (sqlite3_int64)first_k);
    int src;
    while ((src = sqlite3_step(seg)) == SQLITE_ROW) {
        sqlite3_int64 kk = 0, ph = 0;
        if (!col_int(seg, 0, 1, INT64_MAX, &kk) ||
            !col_blob_len(seg, 1, 64) ||
            !col_int(seg, 2, 1, INT64_MAX, &ph) || (uint64_t)ph > B)
            goto done;
        const uint64_t k = (uint64_t)kk;
        const int is_old = (uint64_t)ph + E <= B;  /* existed at B - E    */
        g_nodus_storage_work.segments_visited++;
        uint8_t a_key[64];
        if (dna_v2_segment_assign_key(sqlite3_column_blob(seg, 1), a_key)
            != 0)
            goto done;
        const uint8_t *root = sqlite3_column_blob(seg, 1);

        uint8_t rfp[ST_R_CAP][64], rsc[ST_R_CAP][64];
        size_t nr = 0;
        if (st_rows_cur(w, k, rfp, rsc, &nr) != 0) goto done;
        if (!is_old && nr != 0) {
            QGP_LOG_ERROR(LOG_TAG, "storage boundary %llu: segment %llu "
                          "was published now but already has rows",
                          (unsigned long long)B, (unsigned long long)k);
            goto done;
        }

        /* prev(k): the previous epoch's holdings */
        uint8_t pfp[ST_R_CAP][64];
        size_t np = 0;
        if (is_old) {
            if (is_b1) {
                uint8_t x3[DNA_V2_STORAGE_HOLDERS][64];
                size_t nx = 0;
                if (!prevset ||
                    nodus_witness_storage_holders(prevset, root, x3, &nx)
                        != 0)
                    goto done;
                for (size_t i = 0; i < nx; i++) memcpy(pfp[np++], x3[i], 64);
            } else {
                for (size_t i = 0; i < nr; i++) memcpy(pfp[np++], rfp[i], 64);
            }
        }

        /* new(k) */
        uint8_t nfp[ST_R_CAP][64];
        size_t nn = 0;
        int holder_departed = 0;
        for (size_t i = 0; i < nr && !holder_departed; i++)
            holder_departed = st_in_list((const uint8_t (*)[64])dep, n_dep,
                                         rfp[i]);
        if (is_old && !holder_departed && copies_old == R) {
            /* join rule: the stored rows + the arrivals */
            size_t nc = 0, idx[ST_R_CAP];
            for (size_t i = 0; i < nr; i++) {
                memcpy(cfp[nc], rfp[i], 64);
                memcpy(csc[nc], rsc[i], 64);
                nc++;
            }
            for (size_t i = 0; i < n_arr; i++) {
                memcpy(cfp[nc], arr[i], 64);
                if (dna_v2_segment_score(a_key, arr[i], csc[nc]) != 0)
                    goto done;
                g_nodus_storage_work.scores_computed++;
                nc++;
            }
            st_select_top((const uint8_t (*)[64])cfp,
                          (const uint8_t (*)[64])csc, nc, R, idx, &nn);
            for (size_t i = 0; i < nn; i++) memcpy(nfp[i], cfp[idx[i]], 64);
        } else {
            size_t idx[ST_R_CAP];
            if (dna_v2_segment_holders_hrw(a_key,
                    (const uint8_t (*)[64])set->fps, set->fail_streak,
                    set->count, R, idx, &nn) != 0)
                goto done;
            g_nodus_storage_work.scores_computed += n_elig;
            for (size_t i = 0; i < nn; i++) memcpy(nfp[i], set->fps[idx[i]], 64);
        }

        /* rows: end the dropped, insert the new */
        for (size_t i = 0; i < nr; i++)
            if (!st_in_list((const uint8_t (*)[64])nfp, nn, rfp[i])) {
                if (st_row_end(w, k, rfp[i], B) != 0 ||
                    st_held_add(w, rfp[i], -1) != 0)
                    goto done;
            }
        for (size_t i = 0; i < nn; i++)
            if (!st_in_list((const uint8_t (*)[64])rfp, nr, nfp[i])) {
                uint8_t sc[64];
                if (dna_v2_segment_score(a_key, nfp[i], sc) != 0 ||
                    st_row_insert(w, k, nfp[i], sc, B) != 0 ||
                    st_held_add(w, nfp[i], +1) != 0)
                    goto done;
            }

        /* counts (K9a): only for a segment that existed at B - E, only for
         * members of set(B) */
        if (is_old) {
            for (size_t i = 0; i < np; i++)
                if (!st_in_list((const uint8_t (*)[64])nfp, nn, pfp[i])) {
                    long m = st_find_fp((const uint8_t (*)[64])set->fps,
                                        set->count, pfp[i]);
                    if (m >= 0) ended[m]++;
                }
            for (size_t i = 0; i < nn; i++)
                if (!st_in_list((const uint8_t (*)[64])pfp, np, nfp[i])) {
                    long m = st_find_fp((const uint8_t (*)[64])set->fps,
                                        set->count, nfp[i]);
                    if (m < 0) goto done;     /* new is drawn from set(B) */
                    n_new[m]++;
                }
        }
    }
    if (src != SQLITE_DONE) goto done;
    sqlite3_finalize(seg);
    seg = NULL;
no_segments:

    /* ── held_union and n_new per member ─────────────────────────────── */
    for (uint32_t i = 0; i < set->count; i++) {
        uint64_t hd = 0;
        if (st_held_get(w, set->fps[i], &hd) != 0) goto done;
        if (event) {
            if (dna_ck_add_u64(hd, ended[i], &held_union[i]) != 0) goto done;
        } else if (is_b1) {
            /* B1 without an event: the E-s3 table (absent row = 0) */
            sqlite3_stmt *xs = NULL;
            if (sqlite3_prepare_v2(w->db,
                    "SELECT ended_x, new_x FROM v2_storage_xfer_diff WHERE "
                    "node_fp = ?1", -1, &xs, NULL) != SQLITE_OK)
                goto done;
            sqlite3_bind_blob(xs, 1, set->fps[i], 64, SQLITE_STATIC);
            int xr = sqlite3_step(xs);
            sqlite3_int64 ex = 0, nx = 0;
            int okx = xr == SQLITE_DONE ||
                      (xr == SQLITE_ROW && col_int(xs, 0, 0, INT64_MAX, &ex)
                       && col_int(xs, 1, 0, INT64_MAX, &nx));
            sqlite3_finalize(xs);
            if (!okx) goto done;
            if (dna_ck_add_u64(hd, (uint64_t)ex, &held_union[i]) != 0)
                goto done;
            n_new[i] = (uint64_t)nx;
        } else {
            held_union[i] = hd;
        }
    }

    /* ── the one-use table, the basis and the state ──────────────────── */
    /* plan §8.6 "The one-use table is dropped after B1": the table goes
     * with the state's xfer flag (written 0 below, in this transaction).
     * The per-open shape check accepts its absence only while the state
     * row says xfer = 0 (nodus_witness_v2_schema.c s20_storage_shape_ok). */
    /* Dropped at the FIRST generation-6 boundary whichever way it was
     * reached (xfer = 1 after E-s2, or xfer = 0 on a chain with no
     * set(H2), where the table was created by the rung and never used):
     * IF EXISTS, so later boundaries find nothing to do. */
    if (sqlite3_exec(w->db, "DROP TABLE IF EXISTS v2_storage_xfer_diff",
                     NULL, NULL, NULL) != SQLITE_OK)
        goto done;
    if (st_basis_store(w, event || is_b1 || !present,
                       (const uint8_t (*)[64])elig, n_elig, R, B, 0) != 0)
        goto done;
    ret = 0;
done:
    if (seg) sqlite3_finalize(seg);
    free(prevset);
    free(ended);
    free(csc);
    free(cfp);
    free(arr);
    free(dep);
    free(basis);
    free(elig);
    return ret;
}

/* STEP 5 from generation 6: freeze storage_set(B) from the status index,
 * assign (§8.5), K9 grace from the assignment counts, write the set rows
 * and the members' v2_storage_member_epoch rows. @return 0 / -2. */
int nodus_witness_storage_freeze_gen6(nodus_witness_t *w, uint64_t B,
                                      uint32_t R, uint32_t set_cap,
                                      nodus_storage_boundary_t *out) {
    if (!w || !w->db || !out) return -2;
    if (B > ST_STORE_MAX) return -2;
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    dna_v2_storage_node_row_t *rows = NULL;
    size_t n = 0;
    if (nodus_witness_storage_registry_load_status(
            w, DNA_V2_STORAGE_ACTIVE, &rows, &n) != 0)
        return -2;
    g_nodus_storage_work.registry_rows_read += n;
    int ret = -2;
    nodus_storage_set_t *set = calloc(1, sizeof(*set));
    uint64_t *hu = calloc(DNA_V2_STORAGE_SET_CAP, sizeof(*hu));
    uint64_t *nn = calloc(DNA_V2_STORAGE_SET_CAP, sizeof(*nn));
    if (!set || !hu || !nn) goto done;
    for (size_t i = 0; i < n; i++) {         /* node_fp ASC */
        if (set->count >= set_cap) goto done;   /* the generation's cap */
        memcpy(set->fps[set->count], rows[i].node_fp, 64);
        set->fail_streak[set->count] = rows[i].fail_streak;
        set->grace_until[set->count] = rows[i].grace_until;
        set->count++;
    }
    if (dna_v2_storage_set_hash_lim(B, (const uint8_t (*)[64])set->fps,
                                    set->count, set_cap,
                                    set->set_hash) != 0)
        goto done;
    if (st_assign_boundary(w, B, set, R, out->n_published, hu, nn) != 0)
        goto done;
    for (uint32_t i = 0; i < set->count; i++) {      /* node_fp ASC */
        const uint64_t old = set->grace_until[i];
        uint64_t nv = 0;
        if (nodus_storage_grace_next(old, B, nn[i], E, &nv) != 0 ||
            nv > ST_STORE_MAX) {
            QGP_LOG_ERROR(LOG_TAG, "storage boundary %llu: grace_until "
                          "overflow (%llu new segments)",
                          (unsigned long long)B, (unsigned long long)nn[i]);
            goto done;
        }
        if (st_grace_write(w, set->fps[i], old, nv) != 0) goto done;
        set->grace_until[i] = nv;
    }
    if (st_set_write(w, B, set) != 0) goto done;
    for (uint32_t i = 0; i < set->count; i++)
        if (st_member_epoch_put(w, B, set->fps[i], hu[i], nn[i]) != 0)
            goto done;
    out->set_count = set->count;
    ret = 0;
done:
    free(nn);
    free(hu);
    free(set);
    free(rows);
    return ret;
}

/* E-s1 callback: one call per (m, k) with at least one flag set = one
 * segment of the union holders(k, set(H)) U holders(k, set(H - E)) of m. */
static int st_rel_union(void *ud, size_t member, uint64_t k, uint64_t pub,
                        int in_cur, int in_prev) {
    (void)k;
    (void)pub;
    (void)in_cur;
    (void)in_prev;
    uint64_t *cnt = ud;
    cnt[member]++;                       /* <= the segment count: no wrap */
    return 0;
}

int nodus_witness_storage_gen6_transition(nodus_witness_t *w, uint64_t h) {
    if (!w || !w->db) return -2;
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    {
        uint64_t v = 0;
        int rc = nodus_chain_config_get_u64(
                     w, (uint8_t)DNAC_CFG_RULESET_GEN_ROLES, h, 0ULL, &v);
        if (rc < 0) {
            QGP_LOG_ERROR(LOG_TAG, "storage transition at %llu: the "
                          "RULESET_GEN_ROLES history is unreadable",
                          (unsigned long long)h);
            return -2;
        }
        if (rc != 0) return 0;           /* storage gate closed: nothing  */
    }
    int present = 0, xfer = 0;
    uint32_t copies = 0;
    uint64_t bnd = 0;
    if (st_state_get(w, &present, &copies, &bnd, &xfer) != 0 || present) {
        QGP_LOG_ERROR(LOG_TAG, "storage transition at %llu: the assignment "
                      "state is %s - the edge runs once on empty tables",
                      (unsigned long long)h,
                      present ? "already written" : "unreadable");
        return -2;
    }
    const uint64_t H2 = (h / E) * E;      /* the last boundary < A         */
    const uint32_t R0 = (uint32_t)DNAC_STORAGE_COPIES_DEFAULT;  /* §8.6 E-s2:
        * param 25 cannot be effective before B1 (votable only under
        * generation >= 6, wait >= one epoch) */
    int ret = -2;
    nodus_storage_set_t *cur = calloc(1, sizeof(*cur));
    nodus_storage_set_t *prev = calloc(1, sizeof(*prev));
    uint64_t *cnt = calloc(DNA_V2_STORAGE_SET_CAP, sizeof(*cnt));
    uint64_t *endx = calloc(DNA_V2_STORAGE_SET_CAP, sizeof(*endx));
    uint64_t *newx = calloc(DNA_V2_STORAGE_SET_CAP, sizeof(*newx));
    uint8_t (*elig)[64] = calloc(DNA_V2_STORAGE_SET_CAP, 64);
    st_seg_t *segs = NULL;
    size_t n_segs = 0, n_elig = 0;
    if (!cur || !prev || !cnt || !endx || !newx || !elig) goto done;

    /* ── E-s1: the union counts of the two epochs settled at B1 and
     *    B1 + E, by the existing XOR walk ────────────────────────────── */
    for (int which = 0; which < 2; which++) {
        const uint64_t H = which == 0 ? (H2 >= E ? H2 - E : 0) : H2;
        if (H == 0) continue;
        int rc = nodus_witness_storage_set_get(w, H, cur);
        if (rc == 1) continue;                    /* no set(H): nothing   */
        if (rc != 0) goto done;
        rc = nodus_witness_storage_set_get(w, H - E, prev);
        if (rc < 0) goto done;
        if (rc == 1) prev->count = 0;
        free(segs);
        segs = NULL;
        n_segs = 0;
        if (st_segments_load(w, H, &segs, &n_segs) != 0) goto done;
        memset(cnt, 0, cur->count * sizeof(*cnt));
        if (st_member_walk(cur, prev, H, segs, n_segs, st_rel_union, cnt)
            != 0)
            goto done;
        for (uint32_t i = 0; i < cur->count; i++)
            if (st_member_epoch_put(w, H, cur->fps[i], cnt[i], 0) != 0)
                goto done;
    }

    /* ── E-s2: the rendezvous rows of every published segment, over the
     *    eligible members of set(H2), R = 4; basis; state ──────────────── */
    {
        int rc = H2 >= E ? nodus_witness_storage_set_get(w, H2, cur) : 1;
        if (rc < 0) goto done;
        const int have_set = rc == 0;     /* an EMPTY frozen set is a set */
        if (!have_set) memset(cur, 0, sizeof(*cur)); /* no set: empty basis */
        for (uint32_t i = 0; i < cur->count; i++)
            if (cur->fail_streak[i] < DNA_V2_STORAGE_FAIL_LIMIT)
                memcpy(elig[n_elig++], cur->fps[i], 64);
        free(segs);
        segs = NULL;
        n_segs = 0;
        if (st_segments_load(w, UINT64_MAX, &segs, &n_segs) != 0) goto done;
        /* publication and the freeze run in the same boundary, so a
         * published segment implies a frozen set at H2 (empty included) */
        if (!have_set && n_segs > 0) {
            QGP_LOG_ERROR(LOG_TAG, "storage transition at %llu: %zu "
                          "segments are published but storage_set(%llu) "
                          "does not exist", (unsigned long long)h, n_segs,
                          (unsigned long long)H2);
            goto done;
        }
        const uint64_t B1 = H2 + E;
        for (size_t s = 0; s < n_segs; s++) {
            if (segs[s].published_height > H2) goto done;   /* none later */
            uint8_t a_key[64];
            size_t idx[ST_R_CAP], nh = 0;
            if (dna_v2_segment_assign_key(segs[s].root, a_key) != 0 ||
                dna_v2_segment_holders_hrw(a_key,
                    (const uint8_t (*)[64])cur->fps, cur->fail_streak,
                    cur->count, R0, idx, &nh) != 0)
                goto done;
            for (size_t i = 0; i < nh; i++) {
                uint8_t sc[64];
                if (dna_v2_segment_score(a_key, cur->fps[idx[i]], sc) != 0 ||
                    st_row_insert(w, segs[s].k, cur->fps[idx[i]], sc, B1)
                        != 0 ||
                    st_held_add(w, cur->fps[idx[i]], +1) != 0)
                    goto done;
            }
            /* ── E-s3: against XOR(set(H2)) ─────────────────────────── */
            uint8_t x3[DNA_V2_STORAGE_HOLDERS][64];
            size_t nx = 0;
            if (nodus_witness_storage_holders(cur, segs[s].root, x3, &nx)
                != 0)
                goto done;
            for (size_t i = 0; i < nx; i++) {       /* in XOR, not in HRW */
                int inh = 0;
                for (size_t t = 0; t < nh; t++)
                    if (memcmp(cur->fps[idx[t]], x3[i], 64) == 0) inh = 1;
                if (!inh) {
                    long m = st_find_fp((const uint8_t (*)[64])cur->fps,
                                        cur->count, x3[i]);
                    if (m < 0) goto done;
                    endx[m]++;
                }
            }
            for (size_t t = 0; t < nh; t++) {       /* in HRW, not in XOR */
                int inx = 0;
                for (size_t i = 0; i < nx; i++)
                    if (memcmp(cur->fps[idx[t]], x3[i], 64) == 0) inx = 1;
                if (!inx) newx[idx[t]]++;
            }
        }
        for (uint32_t i = 0; i < cur->count; i++) {
            if (endx[i] == 0 && newx[i] == 0) continue;
            sqlite3_stmt *st = NULL;
            if (sqlite3_prepare_v2(w->db,
                    "INSERT INTO v2_storage_xfer_diff (node_fp, ended_x, "
                    "new_x) VALUES (?1, ?2, ?3)", -1, &st, NULL)
                != SQLITE_OK)
                goto done;
            sqlite3_bind_blob(st, 1, cur->fps[i], 64, SQLITE_STATIC);
            sqlite3_bind_int64(st, 2, (sqlite3_int64)endx[i]);
            sqlite3_bind_int64(st, 3, (sqlite3_int64)newx[i]);
            int sr = sqlite3_step(st);
            sqlite3_finalize(st);
            if (sr != SQLITE_DONE) goto done;
        }
        /* xfer = 1 (the one-use XOR-vs-rendezvous table is pending for
         * B1) only when there IS a frozen set(H2) to transition from; with
         * none, B1 is an ordinary first freeze (no XOR history exists) */
        if (st_basis_store(w, 1, (const uint8_t (*)[64])elig, n_elig, R0, H2,
                           have_set ? 1 : 0) != 0)
            goto done;
    }
    ret = 0;
done:
    free(segs);
    free(elig);
    free(newx);
    free(endx);
    free(cnt);
    free(prev);
    free(cur);
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

    int gen6 = 0;
    /* ── 0. GATE: param 18 in effect at B, read FIRST ──────────────── */
    /* HF-6 slice 8c (design docs/plans/2026-10-03-hf5-validator-owner-
     * stake-design.md rev 6 §8 "Storage sınır kapısı param 18'i okur"):
     * the generation-4 vote RULESET_GEN_ROLES — the SAME id the edge
     * (nodus_witness_v2_apply.c phase_6b_gen4_edge) fires on, so the gate
     * opens at the first boundary at or after the edge's H. */
    {
        uint64_t v = 0;
        int rc = nodus_chain_config_get_u64(
                     w, (uint8_t)DNAC_CFG_RULESET_GEN_ROLES, B, 0ULL, &v);
        if (rc < 0) {
            QGP_LOG_ERROR(LOG_TAG, "storage boundary %llu: the "
                          "RULESET_GEN_ROLES history is unreadable",
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
            QGP_LOG_ERROR(LOG_TAG, "storage boundary %llu: param 18 is in "
                          "effect but the SYSTEM runtime is generation %u",
                          (unsigned long long)B, (unsigned)rt->generation);
            return -2;
        }
        /* THE generation-6 regime of the boundary (plan §8.6, B >= B1): the
         * SYSTEM runtime's generation. A-1 and A are never boundaries, so
         * this agrees with "param 24 in effect at B"; it is cross-checked
         * below against that very rule - a disagreement is a FAULT. */
        gen6 = rt->generation >= NODUS_RT_GEN_TRIE;
    }
    {
        const int g24 = nodus_witness_storage_gen6_at(w, B);
        if (g24 < 0 || g24 != gen6) {
            QGP_LOG_ERROR(LOG_TAG, "storage boundary %llu: the runtime "
                          "generation says gen6=%d, param 24 says %d",
                          (unsigned long long)B, gen6, g24);
            return -2;
        }
    }
    uint32_t copies = 0, set_cap = 0, bm_cap = 0;
    if (gen6 && (nodus_witness_storage_copies_at(w, B, &copies) != 0 ||
                 nodus_witness_storage_limits_at(w, B, &set_cap, &bm_cap)
                     != 0))
        return -2;                      /* set_cap = 1024 from generation 6 */
    (void)bm_cap;
    out->active = 1;

    if (st_settle(w, B, chain_id, gen6, out) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "storage settlement failed at %llu",
                      (unsigned long long)B);
        return -2;
    }
    if (nodus_witness_storage_prune(w, B, gen6) != 0 ||
        st_release(w, B, chain_id, gen6, out) != 0 ||
        st_publish(w, B, gen6, out) != 0 ||
        (gen6 ? nodus_witness_storage_freeze_gen6(w, B, copies, set_cap, out)
              : st_freeze(w, B, out)) != 0) {
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
