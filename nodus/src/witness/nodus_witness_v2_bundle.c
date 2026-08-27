/**
 * @file nodus/src/witness/nodus_witness_v2_bundle.c
 * @brief Ledger V2 O15E Faz D — canonical successor genesis bundle.
 *
 * Contract, layout and the integrity model are in the header. This file
 * is a CONTAINER codec: it serializes already-canonical committed row
 * bytes in PRIMARY-KEY order and replays them into a fresh DB. It
 * computes NO consensus value; the joiner's genesis re-derivation and
 * the local pin comparison are the integrity check.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "witness/nodus_witness_v2_bundle.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "witness/nodus_witness_v2_claims.h"

#include "dnac/vset_wire.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "W_V2BUNDLE"

/* The genesis-time base tables carried, in a FIXED order (both sides
 * agree on it). Each is serialized in PRIMARY-KEY / deterministic order.
 * Snapshots (validator_set_snapshots) are NOT carried — the joiner
 * rebuilds them from the transferred validators via
 * nodus_witness_vset_commit_genesis, byte-identically (the seam's own
 * bootstrap all-zero-seed branch). */
typedef struct { const char *name; const char *order_by; } bundle_table_t;
static const bundle_table_t BUNDLE_TABLES[] = {
    /* ORDER BY columns are the tables' actual PRIMARY KEYs (verified
     * against the DDL: nodus_witness.c validators/delegations/
     * epoch_state/supply_tracking, nodus_witness_chain_config.c). A
     * wrong name would fail the prepare and abort the derivation. */
    { "validators",            "pubkey_hash ASC" },
    { "delegations",           "delegator_hash ASC, validator_hash ASC" },
    { "epoch_state",           "epoch_start_height ASC" },
    { "chain_config_history",  "param_id ASC, effective_block ASC" },
    { "supply_tracking",       "id ASC" },
    /* O15J L1-F1 (HIGH) — validator_stats was MISSING. The producer
     * carries SIX base tables; this table carried five, and
     * validator_stats reaches NO committed root, so a joiner's genesis
     * matched its pin byte-for-byte while its `active_count` stayed at
     * the create_chain_db seed of 0 (nodus_witness.c:285) instead of the
     * producer's value. The divergence was SILENT until the first
     * RETIRING graduation, where v2ep_active_count_dec refuses a counter
     * that cannot absorb a decrement (nodus_witness_v2_epoch.c:253-263)
     * — a -2 fault, i.e. a deterministic halt on that node only.
     * `key` IS the primary key (nodus_witness.c:233-236). */
    { "validator_stats",       "key ASC" },
};
#define BUNDLE_N_TABLES (sizeof(BUNDLE_TABLES) / sizeof(BUNDLE_TABLES[0]))

/* ── a growable byte sink ────────────────────────────────────────────── */
typedef struct { uint8_t *buf; size_t len, cap; int err; } sink_t;

static void sink_put(sink_t *s, const void *p, size_t n) {
    if (s->err) return;
    if (s->len + n > s->cap) {
        size_t nc = s->cap ? s->cap * 2 : 4096;
        while (nc < s->len + n) nc *= 2;
        uint8_t *nb = realloc(s->buf, nc);
        if (!nb) { s->err = 1; return; }
        s->buf = nb; s->cap = nc;
    }
    memcpy(s->buf + s->len, p, n);
    s->len += n;
}
static void sink_u16(sink_t *s, uint16_t v) {
    uint8_t b[2] = { (uint8_t)(v >> 8), (uint8_t)v };
    sink_put(s, b, 2);
}
static void sink_u32(sink_t *s, uint32_t v) {
    uint8_t b[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16),
                     (uint8_t)(v >> 8), (uint8_t)v };
    sink_put(s, b, 4);
}
static void sink_i64(sink_t *s, int64_t v) {
    uint64_t u = (uint64_t)v;
    uint8_t b[8];
    for (int i = 0; i < 8; i++) b[i] = (uint8_t)(u >> (56 - 8 * i));
    sink_put(s, b, 8);
}

/* ── a bounds-checked reader ─────────────────────────────────────────── */
typedef struct { const uint8_t *p; size_t len, off; int err; } rdr_t;

static void rd_take(rdr_t *r, void *out, size_t n) {
    if (r->err || r->off + n > r->len) { r->err = 1; return; }
    if (out) memcpy(out, r->p + r->off, n);
    r->off += n;
}
static uint16_t rd_u16(rdr_t *r) {
    uint8_t b[2]; rd_take(r, b, 2);
    return r->err ? 0 : (uint16_t)((b[0] << 8) | b[1]);
}
static uint32_t rd_u32(rdr_t *r) {
    uint8_t b[4]; rd_take(r, b, 4);
    return r->err ? 0 : ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
                        ((uint32_t)b[2] << 8) | b[3];
}
static int64_t rd_i64(rdr_t *r) {
    uint8_t b[8]; rd_take(r, b, 8);
    if (r->err) return 0;
    uint64_t u = 0;
    for (int i = 0; i < 8; i++) u = (u << 8) | b[i];
    return (int64_t)u;
}

/* ── table (de)serialization ─────────────────────────────────────────── */

static int table_ncols(sqlite3 *db, const char *name, uint16_t *out) {
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT * FROM %s LIMIT 0", name);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int n = sqlite3_column_count(st);
    sqlite3_finalize(st);
    if (n < 1 || n > 4096) return -1;
    *out = (uint16_t)n;
    return 0;
}

static int table_rowcount(sqlite3 *db, const char *name, uint32_t *out) {
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s", name);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int rc = sqlite3_step(st);
    uint32_t c = (rc == SQLITE_ROW) ? (uint32_t)sqlite3_column_int64(st, 0) : 0;
    sqlite3_finalize(st);
    if (rc != SQLITE_ROW) return -1;
    *out = c;
    return 0;
}

static int serialize_table(sqlite3 *db, const bundle_table_t *t, sink_t *s) {
    uint16_t ncols = 0;
    uint32_t nrows = 0;
    if (table_ncols(db, t->name, &ncols) != 0) return -1;
    if (table_rowcount(db, t->name, &nrows) != 0) return -1;

    size_t nl = strlen(t->name);
    if (nl == 0 || nl > 0xFFFF) return -1;
    sink_u16(s, (uint16_t)nl);
    sink_put(s, t->name, nl);
    sink_u32(s, nrows);
    sink_u16(s, ncols);

    char sql[256];
    snprintf(sql, sizeof(sql), "SELECT * FROM %s ORDER BY %s",
             t->name, t->order_by);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;

    uint32_t emitted = 0;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (sqlite3_column_count(st) != (int)ncols) { rc = SQLITE_ERROR; break; }
        for (int c = 0; c < (int)ncols; c++) {
            int ty = sqlite3_column_type(st, c);
            switch (ty) {
            case SQLITE_NULL:
                { uint8_t m = 0; sink_put(s, &m, 1); }
                break;
            case SQLITE_INTEGER:
                { uint8_t m = 1; sink_put(s, &m, 1);
                  sink_i64(s, sqlite3_column_int64(st, c)); }
                break;
            case SQLITE_TEXT: {
                uint8_t m = 2; sink_put(s, &m, 1);
                const void *p = sqlite3_column_text(st, c);
                int len = sqlite3_column_bytes(st, c);
                sink_u32(s, (uint32_t)len);
                sink_put(s, p, (size_t)len);
                break;
            }
            case SQLITE_BLOB: {
                uint8_t m = 3; sink_put(s, &m, 1);
                const void *p = sqlite3_column_blob(st, c);
                int len = sqlite3_column_bytes(st, c);
                sink_u32(s, (uint32_t)len);
                if (len > 0) sink_put(s, p, (size_t)len);
                break;
            }
            default:                       /* SQLITE_FLOAT: not in these */
                rc = SQLITE_ERROR;
                break;
            }
            if (s->err || rc == SQLITE_ERROR) break;
        }
        if (s->err || rc == SQLITE_ERROR) break;
        emitted++;
    }
    sqlite3_finalize(st);
    if (s->err) return -1;
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) return -1;
    if (emitted != nrows) return -1;       /* mid-scan truncation       */
    return 0;
}

/* Replay one table's rows into a FRESH (empty) table via positional
 * INSERT. SELECT * emits columns in schema order and INSERT ... VALUES
 * consumes them in schema order, so the positional round-trip is exact
 * without carrying column names. */
static int apply_table(sqlite3 *db, rdr_t *r) {
    uint16_t nl = rd_u16(r);
    if (r->err || nl == 0 || nl > 128) return -1;
    char name[129];
    rd_take(r, name, nl);
    if (r->err) return -1;
    name[nl] = '\0';

    /* Only the fixed bundle tables are accepted — a bundle naming any
     * other table is rejected (never a generic INSERT into anything). */
    int known = 0;
    for (size_t i = 0; i < BUNDLE_N_TABLES; i++)
        if (strcmp(BUNDLE_TABLES[i].name, name) == 0) { known = 1; break; }
    if (!known) return -1;

    uint32_t nrows = rd_u32(r);
    uint16_t ncols = rd_u16(r);
    if (r->err || ncols == 0 || ncols > 4096) return -1;

    uint16_t schema_cols = 0;
    if (table_ncols(db, name, &schema_cols) != 0 || schema_cols != ncols)
        return -1;

    /* Fresh-DB guard: create_chain_db may seed a base row (e.g.
     * supply_tracking id=1). Clear the target before planting so the
     * bundle rows are the ONLY rows and no INSERT collides. The joiner
     * runs this inside its own BEGIN, so a partial apply rolls back. */
    {
        char del[128];
        snprintf(del, sizeof(del), "DELETE FROM %s", name);
        if (sqlite3_exec(db, del, NULL, NULL, NULL) != SQLITE_OK) return -1;
    }

    /* INSERT INTO <name> VALUES (?1,...,?ncols) — positional. */
    char sql[512];
    int off = snprintf(sql, sizeof(sql), "INSERT INTO %s VALUES (", name);
    for (uint16_t c = 0; c < ncols; c++) {
        int w = snprintf(sql + off, sizeof(sql) - (size_t)off,
                         "%s?%u", c ? "," : "", (unsigned)(c + 1));
        if (w < 0 || (size_t)(off + w) >= sizeof(sql)) return -1;
        off += w;
    }
    if ((size_t)off + 2 >= sizeof(sql)) return -1;
    sql[off++] = ')'; sql[off] = '\0';

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;

    int ok = 0;
    for (uint32_t row = 0; row < nrows; row++) {
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        for (uint16_t c = 0; c < ncols; c++) {
            uint8_t ty = 0;
            rd_take(r, &ty, 1);
            if (r->err) goto done;
            switch (ty) {
            case 0: sqlite3_bind_null(st, c + 1); break;
            case 1: sqlite3_bind_int64(st, c + 1, rd_i64(r)); break;
            case 2:
            case 3: {
                uint32_t len = rd_u32(r);
                if (r->err || r->off + len > r->len) { r->err = 1; goto done; }
                const uint8_t *p = r->p + r->off;
                if (ty == 2)
                    sqlite3_bind_text(st, c + 1, (const char *)p,
                                      (int)len, SQLITE_TRANSIENT);
                else
                    sqlite3_bind_blob(st, c + 1, p, (int)len,
                                      SQLITE_TRANSIENT);
                r->off += len;
                break;
            }
            default: r->err = 1; goto done;
            }
            if (r->err) goto done;
        }
        if (sqlite3_step(st) != SQLITE_DONE) goto done;
    }
    ok = 1;
done:
    sqlite3_finalize(st);
    return ok ? 0 : -1;
}

/* ── build + persist ─────────────────────────────────────────────────── */

/* v2_genesis_bundle singleton (id CHECK = 1); created lazily here so no
 * schema-version bump is needed — additive, S11-and-up only, and only a
 * successor derivation ever writes it. */
static int ensure_bundle_table(sqlite3 *db) {
    return sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS v2_genesis_bundle ("
        "  id INTEGER PRIMARY KEY CHECK(id = 1),"
        "  bundle BLOB NOT NULL)",
        NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}

int nodus_witness_v2_bundle_persist(nodus_witness_t *w) {
    if (!w || !w->db) return -1;
    if (ensure_bundle_table(w->db) != 0) return -1;

    /* the committed genesis manifest bytes (v2_manifests, committed
     * height 0, lowest seq — the authoritative genesis manifest). */
    uint8_t *manifest = NULL;
    size_t mlen = 0;
    {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT manifest FROM v2_manifests "
                "WHERE committed_height = 0 ORDER BY manifest_seq ASC "
                "LIMIT 1",
                -1, &st, NULL) != SQLITE_OK)
            return -1;
        if (sqlite3_step(st) == SQLITE_ROW) {
            int l = sqlite3_column_bytes(st, 0);
            if (l > 0) {
                manifest = malloc((size_t)l);
                if (manifest) {
                    memcpy(manifest, sqlite3_column_blob(st, 0), (size_t)l);
                    mlen = (size_t)l;
                }
            }
        }
        sqlite3_finalize(st);
    }
    if (!manifest || mlen == 0) { free(manifest); return -1; }

    sink_t s = {0};
    sink_put(&s, NODUS_V2_GBUNDLE_MAGIC, NODUS_V2_GBUNDLE_MAGIC_LEN);
    sink_u32(&s, (uint32_t)mlen);
    sink_put(&s, manifest, mlen);
    free(manifest);
    sink_u32(&s, (uint32_t)BUNDLE_N_TABLES);
    for (size_t i = 0; i < BUNDLE_N_TABLES; i++) {
        if (serialize_table(w->db, &BUNDLE_TABLES[i], &s) != 0) {
            free(s.buf);
            return -1;
        }
    }
    if (s.err) { free(s.buf); return -1; }

    /* Idempotent: a matching row is success; a differing row is a fault
     * (two derivations of the same genesis must serialize identically). */
    {
        uint8_t *existing = NULL;
        size_t elen = 0;
        int grc = nodus_witness_v2_bundle_get(w, &existing, &elen);
        if (grc == 0) {
            int same = (elen == s.len &&
                        memcmp(existing, s.buf, s.len) == 0);
            free(existing);
            free(s.buf);
            return same ? 0 : -1;
        }
        if (grc < 0) { free(s.buf); return -1; }
    }

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_genesis_bundle (id, bundle) VALUES (1, ?1)",
            -1, &st, NULL) != SQLITE_OK) {
        free(s.buf);
        return -1;
    }
    sqlite3_bind_blob(st, 1, s.buf, (int)s.len, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    free(s.buf);
    if (rc != SQLITE_DONE) return -1;
    QGP_LOG_INFO(LOG_TAG, "genesis bundle persisted (%zu bytes)", s.len);
    return 0;
}

int nodus_witness_v2_bundle_get(nodus_witness_t *w,
                                uint8_t **out, size_t *len) {
    if (out) *out = NULL;
    if (len) *len = 0;
    if (!w || !w->db || !out || !len) return -1;
    /* No table at all (legacy DB) is "no bundle", not a fault. */
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT bundle FROM v2_genesis_bundle WHERE id = 1",
            -1, &st, NULL) != SQLITE_OK)
        return 1;
    int rc = sqlite3_step(st);
    if (rc != SQLITE_ROW) { sqlite3_finalize(st); return 1; }
    int l = sqlite3_column_bytes(st, 0);
    if (l <= 0) { sqlite3_finalize(st); return -1; }
    uint8_t *b = malloc((size_t)l);
    if (!b) { sqlite3_finalize(st); return -1; }
    memcpy(b, sqlite3_column_blob(st, 0), (size_t)l);
    sqlite3_finalize(st);
    *out = b;
    *len = (size_t)l;
    return 0;
}

/* ── apply on a fresh joiner ─────────────────────────────────────────── */

int nodus_witness_v2_bundle_apply(nodus_witness_t *w2,
                                  const uint8_t *bytes, size_t len,
                                  const uint8_t pin[64]) {
    if (!w2 || !w2->db || !bytes || !pin) return -1;

    rdr_t r = { bytes, len, 0, 0 };
    uint8_t magic[NODUS_V2_GBUNDLE_MAGIC_LEN];
    rd_take(&r, magic, NODUS_V2_GBUNDLE_MAGIC_LEN);
    if (r.err ||
        memcmp(magic, NODUS_V2_GBUNDLE_MAGIC, NODUS_V2_GBUNDLE_MAGIC_LEN) != 0)
        return -1;
    uint32_t mlen = rd_u32(&r);
    if (r.err || mlen == 0 || r.off + mlen > r.len) return -1;
    const uint8_t *manifest = r.p + r.off;
    r.off += mlen;

    /* Whole-adopt atomicity does NOT come from one wrapping SQL
     * transaction — nodus_witness_v2_genesis_ex manages its OWN
     * BEGIN/COMMIT and cannot be nested (the seam calls the derivation
     * steps bare, seam.c:369-458). It comes from the scratch-DB-discard
     * contract: nothing is durable until the caller renames the scratch
     * file up, and the caller clears the scratch on ANY failure. So the
     * base-table plant runs in its OWN self-contained transaction (the
     * seam.c:342-363 carry shape), then the three derivation steps run
     * outside any transaction, exactly as the seam runs them. */
    if (sqlite3_exec(w2->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        return -1;
    {
        uint32_t ntab = rd_u32(&r);
        int bad = (r.err || ntab != BUNDLE_N_TABLES);
        for (uint32_t i = 0; !bad && i < ntab; i++)
            if (apply_table(w2->db, &r) != 0) bad = 1;
        if (!bad && r.off != r.len) bad = 1;   /* trailing bytes reject  */
        if (bad || r.err) {
            (void)sqlite3_exec(w2->db, "ROLLBACK", NULL, NULL, NULL);
            return -1;
        }
    }
    if (sqlite3_exec(w2->db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        (void)sqlite3_exec(w2->db, "ROLLBACK", NULL, NULL, NULL);
        return -1;
    }

    /* Re-derive the genesis in the SEAM's order (load-bearing): vset
     * snapshots feed the SYSTEM payload root that domreg commits, so
     * snapshots FIRST, domreg SECOND, genesis THIRD. Each manages its
     * own transaction; a failure leaves the scratch DB for the caller
     * to discard. */
    if (nodus_witness_vset_commit_genesis(w2, 1) != 0) return -1;
    if (nodus_witness_domreg_init_genesis(w2) != 0) return -1;

    uint8_t vsh[DNA_VSET_HASH_LEN];
    {
        dna_vset_snapshot_t *s0 = NULL;
        uint32_t sn = 0, sq = 0;
        if (nodus_witness_v2_epoch_authority_for_height(w2, 0, &s0,
                                                        &sn, &sq) != 0
            || !s0) { dna_vset_free(&s0); return -1; }
        int hrc = dna_vset_hash(s0, vsh);
        dna_vset_free(&s0);
        if (hrc != 0) return -1;
    }

    /* THE PIN AS ASSERTION: genesis_ex re-derives the genesis BlockID
     * from the replanted state + manifest and REFUSES if it is not
     * byte-identical to `pin`. A wrong bundle dies here; the caller
     * discards the scratch DB, so nothing is adopted. */
    if (nodus_witness_v2_genesis_ex(w2, pin, vsh, 0, manifest, mlen) != 0)
        return -1;

    /* The joiner persists its OWN bundle so it too can serve — and a
     * byte-mismatch vs what it received is a fault (proves the
     * derivation is reproducible). */
    if (nodus_witness_v2_bundle_persist(w2) != 0) return -1;

    QGP_LOG_INFO(LOG_TAG, "%s", "successor genesis adopted from bundle "
                 "(pin re-derivation matched)");
    return 0;
}
