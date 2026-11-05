/**
 * @file nodus/tests/hf9_gen5_replay.h
 * @brief HF-9 WP4, plan row T-7 / D17 report 2 finding 3 (plan :447): "a
 *        generation-<=5 settlement replay over fixture boundaries gives
 *        byte-identical weights, accrual and registry rows before and after
 *        the change". A recorder that test_storage_b2.c (the generation-4
 *        engine twins, which settle real reports over real storage
 *        boundaries) calls after every storage boundary.
 *
 * ── WHAT IT RECORDS ─────────────────────────────────────────────────────
 *  After each storage boundary B of fixture A of the engine twins (the same
 *  place the K9a model runs, test_storage_b2.c apply_both), ONE digest =
 *  SHA3-512 over B and the digests of
 *   - every v2_storage_nodes row  (the registry: fail_streak, grace_until,
 *     status, bond ... - all columns, node_fp ASC),
 *   - every v2_reward_accrual row (the ACCRUAL of the settlement's pay),
 *   - every v2_treasury row       (pool 1's debit),
 *   - every v2_storage_sets / _set_members / _reports row,
 *   - for every member of set(B): nodus_witness_storage_eligible_segments
 *     (the eligible segment list; weight = P x its length) -
 *  each table digest taken over (column type, value) of every column in
 *  ORDER BY key order. Only functions and tables that exist before HF-9 WP4
 *  are used, so the SAME header compiles at the parent commit dffb8cfd9.
 *
 * ── HOW IT IS USED ──────────────────────────────────────────────────────
 *  hf9r_record(w, B) after a boundary; hf9r_finish() at the end of main().
 *  Environment (documented per CLAUDE.md TESTS):
 *   HF9_GEN5_WRITE=<path>   write the recorded sequence there instead of
 *                           comparing (main does this once, at the PARENT
 *                           commit, to make nodus/tests/vectors/
 *                           hf9_gen5_settlement.json);
 *   otherwise the sequence is compared with the file named by the compile
 *   definition HF9_GEN5_SETTLEMENT_PATH (nodus/CMakeLists.txt, target
 *   test_storage_b2): same count, and for each record the same height and
 *   digest. A MISSING or unreadable file, a different count or any
 *   difference is a FAILURE (a missing vector file is missing coverage,
 *   never a pass).
 *  File format: one JSON object per record, in the order recorded:
 *   {"seq": N, "height": H, "digest": "<128 hex>"}
 *
 * ── LEAVES BEHIND ───────────────────────────────────────────────────────
 *  Nothing, except the file named by HF9_GEN5_WRITE.
 *
 * ── HOW IT CAN FALSELY PASS OR SKIP ─────────────────────────────────────
 *  - It only sees boundaries the engine twins reach (g_model_on sections of
 *    test_storage_b2.c); a settlement path the fixtures never run is not
 *    covered.
 *  - A digest of rows proves equality of those rows, not that the rows are
 *    right; "before" is the parent build's own output, so it pins the
 *    CHANGE, not correctness.
 *  - If the parent file was produced by a b2 whose fixture flow differs
 *    from this one (more or fewer boundaries), the counts differ and the
 *    test fails - it cannot pass silently.
 */

#ifndef HF9_GEN5_REPLAY_H
#define HF9_GEN5_REPLAY_H

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_v2_storage.h"
#include "crypto/hash/qgp_sha3.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef HF9_GEN5_SETTLEMENT_PATH
#define HF9_GEN5_SETTLEMENT_PATH NULL
#endif

#define HF9R_MAX 512

typedef struct {
    uint64_t height;
    uint8_t  digest[64];
} hf9r_rec_t;

static hf9r_rec_t g_hf9r[HF9R_MAX];
static size_t g_hf9r_n;

/* digest of every row of `sql` (all columns, type-tagged) into out; 0 / -1 */
static int hf9r_hash_sql(nodus_witness_t *w, const char *sql,
                         uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    size_t cap = 4096, n = 0;
    uint8_t *buf = malloc(cap);
    int rc, bad = buf == NULL;
    while (!bad && (rc = sqlite3_step(st)) == SQLITE_ROW) {
        const int cols = sqlite3_column_count(st);
        for (int c = 0; c < cols && !bad; c++) {
            const int t = sqlite3_column_type(st, c);
            const void *p = NULL;
            int len = 0;
            uint8_t tmp[9];
            size_t tl = 0;
            tmp[tl++] = (uint8_t)t;
            if (t == SQLITE_INTEGER) {
                sqlite3_int64 v = sqlite3_column_int64(st, c);
                for (int i = 0; i < 8; i++) tmp[tl++] = (uint8_t)(v >> (8 * i));
            } else if (t == SQLITE_BLOB || t == SQLITE_TEXT) {
                len = sqlite3_column_bytes(st, c);
                p = t == SQLITE_BLOB ? sqlite3_column_blob(st, c)
                                     : (const void *)sqlite3_column_text(st, c);
                for (int i = 0; i < 4; i++) tmp[tl++] = (uint8_t)(len >> (8 * i));
            }
            if (n + tl + (size_t)len > cap) {
                while (n + tl + (size_t)len > cap) cap *= 2;
                uint8_t *nb = realloc(buf, cap);
                if (!nb) { bad = 1; break; }
                buf = nb;
            }
            memcpy(buf + n, tmp, tl);
            n += tl;
            if (len > 0 && p) { memcpy(buf + n, p, (size_t)len); n += (size_t)len; }
        }
        if (!bad) {                       /* row separator */
            if (n + 1 > cap) {
                uint8_t *nb = realloc(buf, cap * 2);
                if (!nb) { bad = 1; break; }
                buf = nb;
                cap *= 2;
            }
            buf[n++] = 0xFF;
        }
    }
    sqlite3_finalize(st);
    if (bad) { free(buf); return -1; }
    int r = qgp_sha3_512(buf, n, out) == 0 ? 0 : -1;
    free(buf);
    return r;
}

/* record the digest for boundary B. 0 / -1 */
static int hf9r_record(nodus_witness_t *w, uint64_t B) {
    static const char *const sql[] = {
        "SELECT * FROM v2_storage_nodes ORDER BY node_fp",
        "SELECT * FROM v2_reward_accrual ORDER BY owner_fp",
        "SELECT * FROM v2_treasury ORDER BY pool_id",
        "SELECT * FROM v2_storage_sets ORDER BY epoch_start",
        "SELECT * FROM v2_storage_set_members ORDER BY epoch_start, node_fp",
        "SELECT * FROM v2_storage_reports ORDER BY epoch_start, seat"
    };
    if (g_hf9r_n >= HF9R_MAX) return -1;
    uint8_t pre[8 + 7 * 64 + 8];
    size_t off = 0;
    for (int i = 0; i < 8; i++) pre[off++] = (uint8_t)(B >> (8 * i));
    for (size_t i = 0; i < sizeof(sql) / sizeof(sql[0]); i++) {
        if (hf9r_hash_sql(w, sql[i], pre + off) != 0) return -1;
        off += 64;
    }
    /* the eligible lists (weights) of every member of set(B) */
    nodus_storage_set_t *set = calloc(1, sizeof(*set));
    if (!set) return -1;
    uint8_t lists[64] = { 0 };
    int src = nodus_witness_storage_set_get(w, B, set);
    if (src < 0) { free(set); return -1; }
    if (src == 0) {
        size_t cap = 4096, n = 0;
        uint8_t *buf = malloc(cap);
        uint64_t *ks = malloc(1024 * sizeof(*ks));
        if (!buf || !ks) { free(buf); free(ks); free(set); return -1; }
        for (uint32_t i = 0; i < set->count; i++) {
            size_t nk = 0;
            int er = nodus_witness_storage_eligible_segments(
                         w, B, set->fps[i], ks, 1024, &nk);
            if (er < 0 || n + 64 + 8 + nk * 8 > cap) {
                if (er < 0) { free(buf); free(ks); free(set); return -1; }
                while (n + 64 + 8 + nk * 8 > cap) cap *= 2;
                uint8_t *nb = realloc(buf, cap);
                if (!nb) { free(buf); free(ks); free(set); return -1; }
                buf = nb;
            }
            memcpy(buf + n, set->fps[i], 64); n += 64;
            for (int b = 0; b < 8; b++) buf[n++] = (uint8_t)((uint64_t)nk >> (8 * b));
            for (size_t j = 0; j < nk; j++)
                for (int b = 0; b < 8; b++) buf[n++] = (uint8_t)(ks[j] >> (8 * b));
        }
        int r = qgp_sha3_512(buf, n, lists);
        free(buf);
        free(ks);
        if (r != 0) { free(set); return -1; }
    }
    free(set);
    memcpy(pre + off, lists, 64);
    off += 64;
    g_hf9r[g_hf9r_n].height = B;
    if (qgp_sha3_512(pre, off, g_hf9r[g_hf9r_n].digest) != 0) return -1;
    g_hf9r_n++;
    return 0;
}

static void hf9r_hex(const uint8_t *d, char out[129]) {
    static const char *h = "0123456789abcdef";
    for (int i = 0; i < 64; i++) { out[2 * i] = h[d[i] >> 4]; out[2 * i + 1] = h[d[i] & 15]; }
    out[128] = 0;
}

/* write or compare; 0 pass / -1 fail (the reason on stderr) */
static int hf9r_finish(void) {
    const char *wr = getenv("HF9_GEN5_WRITE");
    char hex[129];
    if (wr && *wr) {
        FILE *f = fopen(wr, "w");
        if (!f) { fprintf(stderr, "hf9r: cannot write %s\n", wr); return -1; }
        fprintf(f, "[\n");
        for (size_t i = 0; i < g_hf9r_n; i++) {
            hf9r_hex(g_hf9r[i].digest, hex);
            fprintf(f, "{\"seq\": %zu, \"height\": %llu, \"digest\": \"%s\"}%s\n",
                    i, (unsigned long long)g_hf9r[i].height, hex,
                    i + 1 < g_hf9r_n ? "," : "");
        }
        fprintf(f, "]\n");
        fclose(f);
        fprintf(stderr, "hf9r: wrote %zu records to %s\n", g_hf9r_n, wr);
        return 0;
    }
    const char *path = HF9_GEN5_SETTLEMENT_PATH;
    FILE *f = path ? fopen(path, "r") : NULL;
    if (!f) {
        fprintf(stderr, "hf9r: the vector file %s is missing - the "
                "generation-<=5 replay is NOT compared (failure, not a "
                "pass)\n", path ? path : "(no path compiled)");
        return -1;
    }
    char line[512];
    size_t i = 0;
    int bad = 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned long long h = 0;
        unsigned long s = 0;
        char dg[129] = { 0 };
        const char *p = strstr(line, "\"seq\":");
        const char *q = strstr(line, "\"height\":");
        const char *r = strstr(line, "\"digest\": \"");
        if (!p || !q || !r) continue;
        if (sscanf(p, "\"seq\": %lu", &s) != 1 ||
            sscanf(q, "\"height\": %llu", &h) != 1 ||
            sscanf(r, "\"digest\": \"%128[0-9a-f]", dg) != 1) { bad = 1; break; }
        if (i >= g_hf9r_n || s != i || h != g_hf9r[i].height) { bad = 1; break; }
        hf9r_hex(g_hf9r[i].digest, hex);
        if (strcmp(hex, dg) != 0) {
            fprintf(stderr, "hf9r: record %zu (boundary %llu) differs from "
                    "the parent's settlement digest\n", i, h);
            bad = 1;
            break;
        }
        i++;
    }
    fclose(f);
    if (bad || i != g_hf9r_n) {
        fprintf(stderr, "hf9r: generation-<=5 settlement replay MISMATCH "
                "(%zu of %zu records matched)\n", i, g_hf9r_n);
        return -1;
    }
    fprintf(stderr, "hf9r: %zu boundary digests identical to the parent's\n", i);
    return 0;
}

#endif /* HF9_GEN5_REPLAY_H */
