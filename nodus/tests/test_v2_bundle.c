/**
 * @file nodus/tests/test_v2_bundle.c
 * @brief Ledger V2 O15E Faz D — the genesis bundle codec + pinned join.
 *
 * A SOURCE fixture derives a successor genesis, persists the canonical
 * bundle, and serves it; a JOINER fixture with an empty DB re-derives the
 * genesis from the bundle bytes and adopts it ONLY when the derived
 * BlockID equals the pin. Byte-for-byte comparison of the five base
 * tables and the genesis identity proves the derivation is reproducible;
 * the adversarial matrix proves a wrong pin / malformed bundle is
 * rejected with no adoption.
 *
 * Driven through the REAL production functions
 * (nodus_witness_v2_bundle_persist / _get / _apply) over real committed
 * fixtures — no parallel serializer.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "crypto/hash/qgp_sha3.h"

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_v2_bundle.h"
#include "witness/nodus_witness_v2_claims.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/dnac.h"
#include "dnac/validator.h"

#include "../tests/v2_genesis_fixture.h"

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

#define N_VAL 3

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain_id[32];
    uint8_t          genesis_id[64];
} fixture_t;

static void rmrf(const char *path) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    if (system(cmd) != 0) { /* best effort */ }
}
static int run_sql(sqlite3 *db, const char *sql) {
    char *e = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &e);
    if (e) sqlite3_free(e);
    return rc == SQLITE_OK ? 0 : -1;
}

static int seed_validators(nodus_witness_t *w) {
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < N_VAL; i++) {
        dnac_validator_record_t v;
        memset(&v, 0, sizeof(v));
        for (size_t b = 0; b < DNAC_PUBKEY_SIZE; b++)
            v.pubkey[b] = (uint8_t)(0x22 * (i + 1) + (b & 0x3F));
        v.self_stake         = 0;
        v.status             = DNAC_VALIDATOR_ACTIVE;
        v.active_since_block = 1;
        uint8_t fpr[64];
        if (qgp_sha3_512(v.pubkey, DNAC_PUBKEY_SIZE, fpr) != 0) return -1;
        for (int b = 0; b < 64; b++) {
            v.unstake_destination_fp[2 * b]     = hexd[fpr[b] >> 4];
            v.unstake_destination_fp[2 * b + 1] = hexd[fpr[b] & 0xF];
        }
        v.unstake_destination_fp[128] = '\0';
        if (nodus_validator_insert(w, &v) != 0) return -1;
    }
    return 0;
}

/* Open a chain DB at S11 with the base tables seeded, but NOT yet a
 * genesis — the SOURCE fixture then commits genesis (which persists the
 * bundle via the seam step; here we call bundle_persist directly since
 * the seam is activation-gated). The JOINER fixture opens empty. */
static int fx_open(fixture_t *fx, const char *tag, int with_genesis) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_bundle_%s_XXXXXX", tag);
    if (!mkdtemp(fx->dir)) return -1;
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);

    uint8_t cid16[16];
    memset(cid16, 0x7B, sizeof(cid16));
    if (nodus_witness_create_chain_db(fx->w, cid16) != 0) return -1;
    if (nodus_witness_db_migrate_v2s11(fx->w) != 0) return -1;
    if (nodus_chain_config_db_migrate(fx->w) != 0) return -1;

    if (!with_genesis) return 0;

    if (run_sql(fx->w->db,
            "INSERT OR REPLACE INTO supply_tracking (id, genesis_supply, "
            "total_burned, total_minted, current_supply, last_tx_hash, "
            "last_sequence) VALUES (1, 0, 0, 0, 0, zeroblob(64), 0)") != 0)
        return -1;
    if (seed_validators(fx->w) != 0) return -1;
    /* a chain_config_history row so that table is NON-EMPTY in the
     * bundle (a realistic successor carries CC rows from the terminal
     * carry) — real columns: new_value/commit_block/tx_hash. */
    if (run_sql(fx->w->db,
            "INSERT INTO chain_config_history (param_id, new_value, "
            "effective_block, commit_block, tx_hash, proposal_nonce, "
            "created_at_unix) "
            "VALUES (4, 3, 100, 99, zeroblob(64), 7, 0)") != 0)
        return -1;
    if (nodus_witness_vset_commit_genesis(fx->w, 1) != 0) return -1;

    uint8_t vset[64];
    memset(vset, 0x77, sizeof(vset));
    if (v2x_genesis_min(fx->w, vset, fx->genesis_id, NULL) != 0) return -1;
    if (nodus_witness_v2_chain_id(fx->w, fx->chain_id) != 0) return -1;
    return 0;
}

static void fx_close(fixture_t *fx) {
    if (fx->w) {
        if (fx->w->db) sqlite3_close(fx->w->db);
        free(fx->w);
        fx->w = NULL;
    }
    if (fx->dir[0]) rmrf(fx->dir);
}

/* Digest of one table's full content in a fixed order. */
static int table_digest(nodus_witness_t *w, const char *name,
                        const char *order, uint8_t out[64]) {
    char sql[256];
    snprintf(sql, sizeof(sql), "SELECT quote(t.*) FROM (SELECT * FROM %s "
             "ORDER BY %s) t", name, order);
    /* quote(t.*) is not portable; digest the row values via a scan */
    snprintf(sql, sizeof(sql), "SELECT * FROM %s ORDER BY %s", name, order);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    /* simple rolling hash: concatenate typed column bytes */
    uint8_t acc[64];
    memset(acc, 0, sizeof(acc));
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        int nc = sqlite3_column_count(st);
        for (int c = 0; c < nc; c++) {
            int ty = sqlite3_column_type(st, c);
            uint8_t h[64];
            const void *p = NULL;
            int len = 0;
            int64_t iv = 0;
            if (ty == SQLITE_INTEGER) { iv = sqlite3_column_int64(st, c);
                p = &iv; len = 8; }
            else if (ty == SQLITE_TEXT) { p = sqlite3_column_text(st, c);
                len = sqlite3_column_bytes(st, c); }
            else if (ty == SQLITE_BLOB) { p = sqlite3_column_blob(st, c);
                len = sqlite3_column_bytes(st, c); }
            else { p = &ty; len = 1; }   /* NULL/other: type marker */
            uint8_t buf[64 + 4096];
            if (len > 4096) { sqlite3_finalize(st); return -1; }
            memcpy(buf, acc, 64);
            if (p && len) memcpy(buf + 64, p, (size_t)len);
            if (qgp_sha3_512(buf, 64 + (size_t)len, h) != 0) {
                sqlite3_finalize(st); return -1;
            }
            memcpy(acc, h, 64);
        }
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;
    memcpy(out, acc, 64);
    return 0;
}

static const struct { const char *name; const char *order; } TBL[] = {
    { "validators",           "pubkey_hash ASC" },
    { "delegations",          "delegator_hash ASC, validator_hash ASC" },
    { "epoch_state",          "epoch_start_height ASC" },
    { "chain_config_history", "param_id ASC, effective_block ASC" },
    { "supply_tracking",      "id ASC" },
};
#define N_TBL (int)(sizeof(TBL)/sizeof(TBL[0]))

static int all_tables_equal(nodus_witness_t *a, nodus_witness_t *b) {
    for (int i = 0; i < N_TBL; i++) {
        uint8_t da[64], db[64];
        if (table_digest(a, TBL[i].name, TBL[i].order, da) != 0) return -1;
        if (table_digest(b, TBL[i].name, TBL[i].order, db) != 0) return -1;
        if (memcmp(da, db, 64) != 0) return 0;
    }
    return 1;
}

/* Count rows across the whole DB (a wrong-pin apply must leave the
 * scratch — here the joiner DB — with NO adopted genesis). */
static int has_v2_block0(nodus_witness_t *w) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT COUNT(*) FROM v2_blocks WHERE global_height = 0",
            -1, &st, NULL) != SQLITE_OK) return -1;
    int n = (sqlite3_step(st) == SQLITE_ROW)
                ? (int)sqlite3_column_int64(st, 0) : -1;
    sqlite3_finalize(st);
    return n;
}

int main(void) {
    /* ── source: derive genesis + persist the bundle ─────────────────── */
    fixture_t src;
    CHECK(fx_open(&src, "src", 1) == 0, "source fixture (genesis)"); OK();

    CHECK(nodus_witness_v2_bundle_persist(src.w) == 0,
          "bundle persists (column names + serialize)"); OK();
    /* idempotent re-persist is success */
    CHECK(nodus_witness_v2_bundle_persist(src.w) == 0,
          "re-persist is idempotent"); OK();

    uint8_t *bundle = NULL;
    size_t blen = 0;
    CHECK(nodus_witness_v2_bundle_get(src.w, &bundle, &blen) == 0 &&
          bundle && blen > 0, "bundle_get returns bytes"); OK();

    /* ── joiner: adopt with the CORRECT pin ──────────────────────────── */
    {
        fixture_t j;
        CHECK(fx_open(&j, "ok", 0) == 0, "joiner fixture (empty)"); OK();
        CHECK(has_v2_block0(j.w) == 0, "joiner starts with no genesis"); OK();

        CHECK(nodus_witness_v2_bundle_apply(j.w, bundle, blen,
                                            src.genesis_id) == 0,
              "apply with correct pin ADOPTS"); OK();
        CHECK(has_v2_block0(j.w) == 1, "joiner now has genesis"); OK();

        /* the derived genesis identity equals the source's */
        uint8_t jid[64];
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(j.w->db,
                      "SELECT block_id FROM v2_blocks WHERE global_height=0",
                      -1, &st, NULL) == SQLITE_OK, "prep jid");
            CHECK(sqlite3_step(st) == SQLITE_ROW &&
                  sqlite3_column_bytes(st, 0) == 64, "jid row");
            memcpy(jid, sqlite3_column_blob(st, 0), 64);
            sqlite3_finalize(st);
            OK();
        }
        CHECK(memcmp(jid, src.genesis_id, 64) == 0,
              "joiner derived the IDENTICAL genesis BlockID"); OK();

        /* every base table is byte-identical to the source */
        CHECK(all_tables_equal(src.w, j.w) == 1,
              "all five base tables byte-identical to source"); OK();

        /* the joiner re-persisted its OWN bundle, byte-equal to received */
        uint8_t *jb = NULL; size_t jlen = 0;
        CHECK(nodus_witness_v2_bundle_get(j.w, &jb, &jlen) == 0,
              "joiner has its own bundle"); OK();
        CHECK(jlen == blen && memcmp(jb, bundle, blen) == 0,
              "joiner's bundle byte-equals the received one"); OK();
        free(jb);
        fx_close(&j);
    }

    /* ── joiner: WRONG pin is rejected, NO adoption ──────────────────── */
    {
        fixture_t j;
        CHECK(fx_open(&j, "badpin", 0) == 0, "joiner fixture"); OK();
        uint8_t wrong[64];
        memcpy(wrong, src.genesis_id, 64);
        wrong[0] ^= 0xFF;                       /* flip one bit           */
        CHECK(nodus_witness_v2_bundle_apply(j.w, bundle, blen, wrong) != 0,
              "wrong pin REJECTS"); OK();
        CHECK(has_v2_block0(j.w) == 0,
              "wrong pin left NO genesis (zero trace)"); OK();
        fx_close(&j);
    }

    /* ── malformed bundles reject ────────────────────────────────────── */
    {
        fixture_t j;
        CHECK(fx_open(&j, "malf", 0) == 0, "joiner fixture"); OK();

        /* bad magic */
        uint8_t *m = malloc(blen); memcpy(m, bundle, blen);
        m[0] ^= 0xFF;
        CHECK(nodus_witness_v2_bundle_apply(j.w, m, blen,
                                            src.genesis_id) != 0,
              "bad magic rejects"); OK();
        CHECK(has_v2_block0(j.w) == 0, "no trace"); OK();
        free(m);

        /* truncated */
        CHECK(nodus_witness_v2_bundle_apply(j.w, bundle, blen - 1,
                                            src.genesis_id) != 0,
              "truncated bundle rejects"); OK();
        CHECK(has_v2_block0(j.w) == 0, "no trace"); OK();

        /* trailing byte */
        uint8_t *t = malloc(blen + 1); memcpy(t, bundle, blen); t[blen] = 0;
        CHECK(nodus_witness_v2_bundle_apply(j.w, t, blen + 1,
                                            src.genesis_id) != 0,
              "trailing byte rejects"); OK();
        CHECK(has_v2_block0(j.w) == 0, "no trace"); OK();
        free(t);

        fx_close(&j);
    }

    /* ── right pin, WRONG bundle: the PIN is the authority (spec §7,
     * "network-supplied farklı pin/genesis reddi") ──────────────────────
     * A DIFFERENT source (a distinct validator set) derives a DIFFERENT
     * genesis. Feeding ITS bundle to a joiner holding the FIRST source's
     * pin must be refused by genesis_ex — proving the pin, not the
     * bundle, is authoritative. This is offset-independent and cannot be
     * vacuous: the two sources provably differ (their genesis ids are
     * compared and required unequal). */
    {
        fixture_t src2;
        CHECK(fx_open(&src2, "src2", 0) == 0, "second source fixture"); OK();
        /* seed a DIFFERENT validator set (shifted pubkeys) */
        {
            static const char hexd[] = "0123456789abcdef";
            for (int i = 0; i < N_VAL; i++) {
                dnac_validator_record_t v;
                memset(&v, 0, sizeof(v));
                for (size_t b = 0; b < DNAC_PUBKEY_SIZE; b++)
                    v.pubkey[b] = (uint8_t)(0x55 * (i + 2) + (b & 0x3F));
                v.self_stake = 0; v.status = DNAC_VALIDATOR_ACTIVE;
                v.active_since_block = 1;
                uint8_t fpr[64];
                CHECK(qgp_sha3_512(v.pubkey, DNAC_PUBKEY_SIZE, fpr) == 0,
                      "fp");
                for (int b = 0; b < 64; b++) {
                    v.unstake_destination_fp[2*b]   = hexd[fpr[b] >> 4];
                    v.unstake_destination_fp[2*b+1] = hexd[fpr[b] & 0xF];
                }
                v.unstake_destination_fp[128] = '\0';
                CHECK(nodus_validator_insert(src2.w, &v) == 0, "insert2");
            }
            OK();
        }
        CHECK(run_sql(src2.w->db,
            "INSERT OR REPLACE INTO supply_tracking (id, genesis_supply, "
            "total_burned, total_minted, current_supply, last_tx_hash, "
            "last_sequence) VALUES (1,0,0,0,0,zeroblob(64),0)") == 0,
            "src2 supply"); OK();
        CHECK(nodus_witness_vset_commit_genesis(src2.w, 1) == 0,
              "src2 vset"); OK();
        uint8_t vset2[64]; memset(vset2, 0x77, 64);
        CHECK(v2x_genesis_min(src2.w, vset2, src2.genesis_id, NULL) == 0,
              "src2 genesis"); OK();
        CHECK(memcmp(src2.genesis_id, src.genesis_id, 64) != 0,
              "the two sources DERIVE DIFFERENT genesis ids"); OK();
        CHECK(nodus_witness_v2_bundle_persist(src2.w) == 0,
              "src2 bundle persists"); OK();

        uint8_t *b2 = NULL; size_t b2len = 0;
        CHECK(nodus_witness_v2_bundle_get(src2.w, &b2, &b2len) == 0 && b2,
              "src2 bundle bytes"); OK();

        fixture_t j;
        CHECK(fx_open(&j, "foreign", 0) == 0, "joiner fixture"); OK();
        /* the FOREIGN bundle (src2) against the FIRST pin (src) */
        CHECK(nodus_witness_v2_bundle_apply(j.w, b2, b2len,
                                            src.genesis_id) != 0,
              "foreign bundle + our pin REJECTS (pin is authority)"); OK();
        CHECK(has_v2_block0(j.w) == 0,
              "foreign bundle left NO genesis (zero trace)"); OK();
        /* and the SAME foreign bundle with ITS OWN pin adopts — proving
         * the reject above was the pin check, not a broken bundle */
        CHECK(nodus_witness_v2_bundle_apply(j.w, b2, b2len,
                                            src2.genesis_id) == 0,
              "foreign bundle + its own pin ADOPTS"); OK();
        free(b2);
        fx_close(&j);
        fx_close(&src2);
    }

    free(bundle);
    fx_close(&src);
    printf("test_v2_bundle: ALL %d CHECKS PASSED\n", g_checks);
    return 0;
}
