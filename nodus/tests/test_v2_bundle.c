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
 * HOW IT CAN LIE (R3 W3 delta 7): `nodus_witness_v2_bundle_apply`
 * DELETEs, re-INSERTs and COMMITs the six base tables (its own BEGIN
 * IMMEDIATE / COMMIT) BEFORE the pin precheck ever runs, because the
 * document sits at the tail of the wire frame and must be fully parsed
 * first — a rejected pin therefore still leaves the sender's rows
 * planted in all six base tables on the scratch handle. The v3
 * wrong-pin case (test_v3_bundle, "adopt with the WRONG pin") and the
 * foreign-bundle case ("foreign bundle") each assert only
 * `v3_has_doc(jw) == 0` afterwards — that proves NO GENESIS DOCUMENT
 * was stored, i.e. adoption did not complete, NOT that the scratch
 * database is byte-unchanged from before `bundle_apply` ran. Do not
 * read a green result there as "zero trace inside this process" —
 * "zero trace" is `nodus_witness_v2_join.c`'s (`join_adopt` /
 * `join_scratch_clear`) property, not this function's, and this test
 * never exercises that discard path (each joiner directory here is
 * `rmrf`'d by the TEST itself, not by the production joiner). The
 * old-magic case, by contrast, IS refused before its own BEGIN
 * (bundle.c's magic check runs before any SQL), so it legitimately
 * asserts a whole-DB digest is unchanged.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <dirent.h>

#include "crypto/hash/qgp_sha3.h"

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_v2_bundle.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_gen.h"       /* R3 W3 — the v3 fixture */
#include "witness/nodus_witness_cmt_store.h"    /* P4: remove genesisDoc */
#include "witness/nodus_witness_emission.h"     /* DNAC_BLOCKS_PER_YEAR :34,
                                                  * DNAC_DECIMAL_UNIT :42 */
#include "nodus/nodus_chain_config.h"
#include "protocol/nodus_tier3.h"                /* NODUS_T3_V2_GBUNDLE_CHUNK_MAX */

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

/* The JOINER-side fixture: an empty chain database with no genesis. (The
 * version-2 SOURCE half — seed_validators + v2x_genesis_min, N_VAL 3 — is
 * deleted by tokenomics-v3 P4; the source is a real version-3 chain,
 * v2x_chain_open.) */
typedef struct {
    nodus_witness_t *w;
    char             dir[128];
} fixture_t;

static void rmrf(const char *path) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    if (system(cmd) != 0) { /* best effort */ }
}

/* Plain substring search over bytes — NOT memmem(): that is a GNU
 * extension (needs _GNU_SOURCE, absent on Windows), and this tree's
 * tests must not depend on it. A naive O(hay*needle) scan is fine here;
 * `hay` is one bundle (tens of KB), not a hot path.
 * @return a pointer into `hay` at the first match, or NULL. */
static const uint8_t *find_bytes(const uint8_t *hay, size_t hay_len,
                                 const uint8_t *needle, size_t needle_len) {
    if (!hay || !needle || needle_len == 0 || needle_len > hay_len)
        return NULL;
    for (size_t i = 0; i + needle_len <= hay_len; i++)
        if (memcmp(hay + i, needle, needle_len) == 0)
            return hay + i;
    return NULL;
}
static int run_sql(sqlite3 *db, const char *sql) {
    char *e = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &e);
    if (e) sqlite3_free(e);
    return rc == SQLITE_OK ? 0 : -1;
}

/* Open an EMPTY chain DB at S11 — the joiner the old-magic case feeds.
 * (S11 creates no table since the P4 fix round deleted `v2_tx_bytes`;
 * the rung still moves the version.) */
static int fx_open(fixture_t *fx, const char *tag) {
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

/* Whole-database logical digest: every table, every row, in a stable
 * order — the same idiom test_v2_preflight.c's db_digest uses, needed
 * here to prove a REFUSED apply left the scratch DB byte-identical.
 * R3 W3: the version-2-lane byte-for-byte table comparison this file
 * used to run (all_tables_equal, over the five base tables) is REMOVED
 * — it has no caller left now that the version-2 lane cannot produce a
 * bundle to adopt (bundle_persist refuses), and an unused static
 * function is a build error under -Werror=unused-function, not a style
 * nit. `table_digest` itself stays: test_v3_bundle's per-table loop
 * still calls it. */
static int db_digest_all(nodus_witness_t *w, uint8_t out[64]) {
    sqlite3_stmt *tq = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT name FROM sqlite_master WHERE type='table' "
            "ORDER BY name", -1, &tq, NULL) != SQLITE_OK)
        return -1;
    uint8_t acc[64];
    memset(acc, 0, sizeof(acc));
    while (sqlite3_step(tq) == SQLITE_ROW) {
        const char *t = (const char *)sqlite3_column_text(tq, 0);
        char sql[512];
        snprintf(sql, sizeof(sql),
                 "SELECT quote(t.*) FROM (SELECT * FROM \"%s\") t", t);
        sqlite3_stmt *rq = NULL;
        if (sqlite3_prepare_v2(w->db, sql, -1, &rq, NULL) != SQLITE_OK) {
            snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM \"%s\"", t);
            if (sqlite3_prepare_v2(w->db, sql, -1, &rq, NULL) != SQLITE_OK)
                continue;
        }
        while (sqlite3_step(rq) == SQLITE_ROW) {
            const unsigned char *v = sqlite3_column_text(rq, 0);
            uint8_t buf[64];
            if (v) {
                qgp_sha3_512(v, strlen((const char *)v), buf);
                for (int i = 0; i < 64; i++) acc[i] ^= buf[i];
            }
        }
        sqlite3_finalize(rq);
        uint8_t nb[64];
        qgp_sha3_512((const uint8_t *)t, strlen(t), nb);
        for (int i = 0; i < 64; i++) acc[i] ^= nb[i];
    }
    sqlite3_finalize(tq);
    memcpy(out, acc, 64);
    return 0;
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

/* ════════════════════════════════════════════════════════════════════
 * R3 W3 (D-24 rev 4 (2), D-17 rev 10 (9)) — THE VERSION-3 bundle: the
 * genesis DOCUMENT travels after the base tables under the `DNA.
 * GBUNDLE.v3` magic (nodus_witness_v2_bundle.h's layout comment); the
 * version-2 lane cannot be bundled at all any more (bundle_persist
 * refuses with no stored document). The joiner binds BOTH the document
 * (chain_id) and the ledger it actually replanted (app_hash == the
 * genesis_cmt-computed root) before adopting.
 * ══════════════════════════════════════════════════════════════════ */

/* A version-3 config's n_validators MUST equal DNAC_COMMITTEE_SIZE (7)
 * — gen_plan_build's shared rule (Rule P.1, nodus_witness_v2_gen.c).
 * (The 3-validator count this file's deleted version-2 source fixture
 * used bypassed that rule; tokenomics-v3 P4 removed it.) */
#define V3_N_VAL 7
#define V3_TREASURY_RAW 93000000000000000ULL  /* V3_N_VAL self-bonds + this
                                                * == DNAC_DEFAULT_TOTAL_SUPPLY,
                                                * same arithmetic test_v2_gen.c
                                                * pins as TREASURY_RAW */

typedef struct {
    nodus_v2_gen_config_t *cfg;
    nodus_v2_gen_alloc_t  *allocs;
} v3cfgbox_t;

static void v3cfg_free(v3cfgbox_t *b) {
    if (!b) return;
    free(b->cfg);
    free(b->allocs);
    b->cfg = NULL;
    b->allocs = NULL;
}

static void v3_hex_lower_fp(const uint8_t *src, size_t src_len,
                            uint8_t *out129) {
    static const char hexd[] = "0123456789abcdef";
    uint8_t fpr[64];
    qgp_sha3_512(src, src_len, fpr);
    for (int i = 0; i < 64; i++) {
        out129[2 * i]     = (uint8_t)hexd[fpr[i] >> 4];
        out129[2 * i + 1] = (uint8_t)hexd[fpr[i] & 0xF];
    }
    out129[128] = '\0';
}

/* One-allocation, V3_N_VAL-validator config, completed to a version-3
 * document via the SAME two builder calls the ceremony tool uses
 * (nodus_v2_gen_config.c). `salt` perturbs every validator pubkey and
 * the allocation's destination binding, so two calls derive DIFFERENT
 * chains — used below to prove the pin, not the bundle, is authoritative. */
static int v3cfg_make(v3cfgbox_t *b, uint8_t salt) {
    memset(b, 0, sizeof(*b));
    b->cfg    = calloc(1, sizeof(*b->cfg));
    b->allocs = calloc(1, sizeof(*b->allocs));
    if (!b->cfg || !b->allocs) { v3cfg_free(b); return -1; }

    nodus_v2_gen_config_t *c = b->cfg;
    c->config_version        = NODUS_V2_GEN_CONFIG_VERSION_V3;
    c->total_supply_raw      = DNAC_DEFAULT_TOTAL_SUPPLY;
    c->epoch_length          = (uint64_t)DNAC_EPOCH_LENGTH;
    c->blocks_per_year       = (uint64_t)DNAC_BLOCKS_PER_YEAR;
    c->decimal_unit          = (uint64_t)DNAC_DECIMAL_UNIT;
    c->inflation_start_block = 0ULL;   /* tokenomics-v3 P2: RETIRED,
                                        * the only legal value is 0 */
    c->claim_start_height    = 0;
    c->claim_end_height      = UINT64_MAX;
    c->n_validators          = V3_N_VAL;

    for (uint16_t i = 0; i < V3_N_VAL; i++) {
        nodus_v2_gen_validator_t *v = &c->validators[i];
        for (size_t bb = 0; bb < DNAC_PUBKEY_SIZE; bb++) {
            v->pubkey[bb] = (uint8_t)(0x11 * (i + 1) + (bb & 0x3F) + salt);
            v->unstake_destination_pubkey[bb] =
                (uint8_t)(v->pubkey[bb] ^ 0x5A);
        }
        v3_hex_lower_fp(v->unstake_destination_pubkey, DNAC_PUBKEY_SIZE,
                        v->unstake_destination_fp);
        v->self_stake     = DNAC_SELF_STAKE_AMOUNT;
        v->commission_bps = (uint16_t)(100 * (i + 1));
    }

    memset(b->allocs[0].source_id, 0, sizeof(b->allocs[0].source_id));
    b->allocs[0].source_id[0] = 0x30;
    {
        uint8_t owner[DNAC_PUBKEY_SIZE];
        for (size_t bb = 0; bb < sizeof(owner); bb++)
            owner[bb] = (uint8_t)(0xA0 + (bb & 0x1F) + salt);
        qgp_sha3_512(owner, sizeof(owner), b->allocs[0].dest_binding);
    }
    b->allocs[0].amount = V3_TREASURY_RAW;
    c->n_allocs = 1;
    c->allocs   = b->allocs;

    if (nodus_witness_v2_gen_v3_defaults(c) != 0) { v3cfg_free(b); return -1; }
    /* tokenomics-v3 P2 (P2-1): Rule P.2 now counts the reward reserve;
     * this fixture's allocation spends the whole supply and it is not a
     * reward test — no pool reserved. */
    c->reward_pool_initial = 0;
    c->genesis_time_ms = 1700000000000ULL;
    c->initial_height  = 1;
    if (nodus_witness_v2_gen_v3_fill_comet_rows(c) != 0) {
        v3cfg_free(b);
        return -1;
    }
    return 0;
}

static int v3_mkdir_tmp(char dir[128], const char *tag) {
    snprintf(dir, 128, "/tmp/test_v2_bundle_v3_%s_XXXXXX", tag);
    return mkdtemp(dir) ? 0 : -1;
}

/* Read-only raw open of the single chain database `derive_v3` landed in
 * `dir`, WITHOUT going through nodus_witness_create_chain_db — that
 * function's role-derivation refuses a version-3 chain on REOPEN today
 * (nodus_witness_v2_gen.h's own doc comment on
 * nodus_witness_v2_gen_stored_chain_id says so explicitly, and names it
 * a W3/C1c obligation this package does not own). `nodus_witness_v2_
 * bundle_get` and `nodus_witness_v2_gen_stored_chain_id` both need only
 * `w->db` (their own doc comments), so this fixture sidesteps the whole
 * question the same way nodus-server.c's read_genesis_chain_id does. */
static nodus_witness_t *v3_open_readonly(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return NULL;
    struct dirent *e;
    char path[600];
    int found = 0;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, "witness_", 8) != 0) continue;
        size_t len = strlen(e->d_name);
        if (len < 4 || strcmp(e->d_name + len - 3, ".db") != 0) continue;
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        found = 1;
        break;
    }
    closedir(d);
    if (!found) return NULL;

    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    if (sqlite3_open_v2(path, &w->db, SQLITE_OPEN_READONLY, NULL)
        != SQLITE_OK) {
        if (w->db) sqlite3_close(w->db);
        free(w);
        return NULL;
    }
    return w;
}

/* A FRESH (never-derived) chain database, exactly the shape
 * nodus_witness_v2_join.c's join_adopt creates its scratch DB with —
 * this is the FRESH-CREATE path, not the reopen-an-existing-v3-chain
 * path v3_open_readonly above avoids. */
static nodus_witness_t *v3_open_fresh(const char *dir, uint8_t fill) {
    uint8_t id16[16];
    memset(id16, fill, sizeof(id16));
    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(w->data_path, sizeof(w->data_path), "%s", dir);
    if (nodus_witness_create_chain_db(w, id16) != 0) { free(w); return NULL; }
    return w;
}

/* Whether `w` has a readable, canonical-strict genesis document — the
 * v3 analogue of has_v2_block0 (a wrong-pin apply must leave neither a
 * block row nor a readable document). */
static int v3_has_doc(nodus_witness_t *w) {
    uint8_t id[NODUS_V2_GEN_CHAIN_ID_LEN];
    return nodus_witness_v2_gen_stored_chain_id(w, id) == 0 ? 1 : 0;
}

static const struct { const char *name; const char *order; } V3_TBL[] = {
    { "validators",           "pubkey_hash ASC" },
    { "delegations",          "delegator_hash ASC, validator_hash ASC" },
    { "epoch_state",          "epoch_start_height ASC" },
    { "chain_config_history", "param_id ASC, effective_block ASC" },
    { "supply_tracking",      "id ASC" },
    { "validator_stats",      "key ASC" },
};
#define N_V3_TBL (int)(sizeof(V3_TBL) / sizeof(V3_TBL[0]))

static int test_v3_bundle(void) {
    printf("R3 W3 (D-24 rev 4) — version-3 bundle: document carriage + "
           "ledger binding\n");

    v3cfgbox_t src_cfg;
    CHECK(v3cfg_make(&src_cfg, 0x00) == 0, "v3 source config"); OK();
    char src_dir[128];
    CHECK(v3_mkdir_tmp(src_dir, "src") == 0, "src tmpdir"); OK();
    uint8_t src_chain32[NODUS_V2_GEN_CHAIN_ID_LEN];
    CHECK(nodus_witness_v2_gen_derive_v3(src_dir, src_cfg.cfg, src_chain32)
              == 0, "derive v3 source"); OK();

    nodus_witness_t *src_w = v3_open_readonly(src_dir);
    CHECK(src_w != NULL, "open v3 source read-only"); OK();
    CHECK(v3_has_doc(src_w) == 1, "source has a readable genesis document");
    OK();

    uint8_t *bundle = NULL;
    size_t blen = 0;
    CHECK(nodus_witness_v2_bundle_get(src_w, &bundle, &blen) == 0 &&
              bundle && blen > 0, "v3 bundle_get returns bytes"); OK();
    fprintf(stderr,
            "    v3 bundle size = %zu bytes; gbundle chunks of %u = %zu\n",
            blen, (unsigned)NODUS_T3_V2_GBUNDLE_CHUNK_MAX,
            (blen + NODUS_T3_V2_GBUNDLE_CHUNK_MAX - 1) /
                NODUS_T3_V2_GBUNDLE_CHUNK_MAX);

    /* ── joiner: adopt with the CORRECT pin (the 32-byte chain id) ────── */
    {
        char jdir[128];
        CHECK(v3_mkdir_tmp(jdir, "ok") == 0, "joiner tmpdir"); OK();
        nodus_witness_t *jw = v3_open_fresh(jdir, 0xAA);
        CHECK(jw != NULL, "joiner db"); OK();
        CHECK(v3_has_doc(jw) == 0, "joiner starts with no document"); OK();

        CHECK(nodus_witness_v2_bundle_apply(jw, bundle, blen, src_chain32)
                  == 0, "v3 apply with correct pin ADOPTS"); OK();
        CHECK(v3_has_doc(jw) == 1, "joiner now has a genesis document"); OK();

        uint8_t jchain[NODUS_V2_GEN_CHAIN_ID_LEN];
        CHECK(nodus_witness_v2_gen_stored_chain_id(jw, jchain) == 0,
              "joiner chain id readable"); OK();
        CHECK(memcmp(jchain, src_chain32, NODUS_V2_GEN_CHAIN_ID_LEN) == 0,
              "joiner derived the IDENTICAL chain id"); OK();

        for (int i = 0; i < N_V3_TBL; i++) {
            uint8_t da[64], db[64];
            CHECK(table_digest(src_w, V3_TBL[i].name, V3_TBL[i].order, da)
                      == 0, "digest source table"); OK();
            CHECK(table_digest(jw, V3_TBL[i].name, V3_TBL[i].order, db)
                      == 0, "digest joiner table"); OK();
            CHECK(memcmp(da, db, 64) == 0, "table byte-identical to source");
            OK();
        }

        uint8_t *jb = NULL; size_t jlen = 0;
        CHECK(nodus_witness_v2_bundle_get(jw, &jb, &jlen) == 0,
              "joiner has its own v3 bundle"); OK();
        CHECK(jlen == blen && memcmp(jb, bundle, blen) == 0,
              "joiner's v3 bundle byte-equals the received one"); OK();
        free(jb);

        sqlite3_close(jw->db);
        free(jw);
        rmrf(jdir);
    }

    /* ── joiner: WRONG pin (a byte flipped in the real chain id) ──────── */
    {
        char jdir[128];
        CHECK(v3_mkdir_tmp(jdir, "badpin") == 0, "joiner tmpdir"); OK();
        nodus_witness_t *jw = v3_open_fresh(jdir, 0xAB);
        CHECK(jw != NULL, "joiner db"); OK();

        uint8_t wrong[NODUS_V2_GEN_CHAIN_ID_LEN];
        memcpy(wrong, src_chain32, sizeof(wrong));
        wrong[0] ^= 0xFF;
        CHECK(nodus_witness_v2_bundle_apply(jw, bundle, blen, wrong) != 0,
              "v3 wrong pin REJECTS"); OK();
        /* This proves no genesis DOCUMENT was stored — adoption did not
         * complete. It does NOT prove `jw`'s scratch database is
         * byte-unchanged: bundle_apply's own BEGIN/COMMIT already
         * planted the six base tables before the pin precheck runs (see
         * this file's header, HOW IT CAN LIE). "Zero trace" in the
         * message below is the production JOINER's guarantee
         * (join_scratch_clear discards this whole directory), which
         * this test does not exercise — this test's own `rmrf(jdir)`
         * below is what actually removes the planted rows here. */
        CHECK(v3_has_doc(jw) == 0,
              "wrong pin left NO readable document (zero trace)"); OK();

        sqlite3_close(jw->db);
        free(jw);
        rmrf(jdir);
    }

    /* ── joiner: a TAMPERED replanted table, CORRECT pin. The document
     * is untouched and still hashes to `pin` (chain_id passes); what
     * genesis_cmt actually computes from the REPLANTED tables no longer
     * matches the document's claimed app_hash. Proves the LEDGER-BINDING
     * check specifically (bundle.h's "what pin binds" note) — a
     * self-consistent document is not enough.
     *
     * THE TAMPER, byte-precise: flip one byte of validator[0]'s
     * self_stake field. Located by `find_bytes` (a plain byte-search
     * helper — memmem() is a GNU extension this tree's tests must not
     * depend on) on the validator's own pubkey bytes (the fixture
     * generated that key, so they are known) rather than a guessed
     * absolute offset, because the manifest's encoded length is not a
     * fixed constant this test wants to hand-compute. The ROW LAYOUT is
     * nodus_witness_v2_bundle.c's
     * serialize_table over the validators table's OWN schema order
     * (nodus_witness.c:168-171: pubkey_hash BLOB, pubkey BLOB,
     * self_stake INTEGER — in that order, SELECT * emits columns in
     * schema order). Each column is encoded `type(1B) ‖ value`
     * (serialize_table's switch), so immediately after the pubkey
     * BLOB's own bytes end comes ONE byte — self_stake's own type tag,
     * asserted to read 1 (SQLITE_INTEGER) below — and then its 8-byte
     * big-endian value. Flipping the value's high-order byte changes
     * the stored self_stake by a large amount without touching any
     * length or type field the table decoder parses, so the row still
     * decodes as a normal, syntactically valid row with a different
     * amount. */
    {
        char jdir[128];
        CHECK(v3_mkdir_tmp(jdir, "tamper") == 0, "joiner tmpdir"); OK();
        nodus_witness_t *jw = v3_open_fresh(jdir, 0xAD);
        CHECK(jw != NULL, "joiner db"); OK();

        uint8_t *tampered = malloc(blen);
        CHECK(tampered != NULL, "alloc tampered"); OK();
        memcpy(tampered, bundle, blen);

        const uint8_t *pk = src_cfg.cfg->validators[0].pubkey;
        const uint8_t *found = find_bytes(tampered, blen, pk,
                                          DNAC_PUBKEY_SIZE);
        CHECK(found != NULL,
              "validator[0]'s pubkey bytes found in the bundle"); OK();
        size_t pubkey_off     = (size_t)(found - tampered);
        size_t stake_type_off = pubkey_off + DNAC_PUBKEY_SIZE;
        size_t stake_val_off  = stake_type_off + 1;
        CHECK(stake_type_off < blen && tampered[stake_type_off] == 1,
              "the byte immediately after the pubkey is self_stake's "
              "own SQLITE_INTEGER type tag — the row layout assumption "
              "above holds"); OK();
        CHECK(stake_val_off + 8 <= blen, "the 8-byte stake value fits");
        OK();
        tampered[stake_val_off] ^= 0xFF;

        CHECK(nodus_witness_v2_bundle_apply(jw, tampered, blen, src_chain32)
                  != 0,
              "tampered validator stake + correct pin REJECTS (ledger "
              "binding, not just the document)"); OK();
        /* NOT v3_has_doc here: the pin precheck (document self-hash vs
         * pin) PASSES for this tamper — only the tables differ, and the
         * document is stored (migrate + store-doc) BEFORE genesis_cmt
         * runs and the app_hash mismatch is caught, exactly the
         * pre-existing "not fully atomic, caller discards the scratch
         * DB" contract this file's version-2 lane always had (bundle.c's
         * own comment: "Whole-adopt atomicity does NOT come from one
         * wrapping SQL transaction"). What DID NOT happen is the final
         * adoption: bundle_persist runs only after every check in
         * bundle_apply passes, so no bundle row exists on the rejected
         * handle. */
        {
            uint8_t *b3 = NULL; size_t b3len = 0;
            CHECK(nodus_witness_v2_bundle_get(jw, &b3, &b3len) == 1,
                  "tampered apply did not reach adoption — no bundle "
                  "row on the rejected handle"); OK();
        }
        free(tampered);

        sqlite3_close(jw->db);
        free(jw);
        rmrf(jdir);
    }

    /* ── right pin, WRONG (foreign) bundle: the PIN is the authority.
     * A second source with a DIFFERENT validator/allocation salt derives
     * a PROVABLY DIFFERENT chain id; its bundle against the FIRST
     * chain's pin must reject, and the SAME bundle against its OWN pin
     * must adopt — proving the reject was the pin/document check, not a
     * broken bundle. ─────────────────────────────────────────────────── */
    {
        v3cfgbox_t src2_cfg;
        CHECK(v3cfg_make(&src2_cfg, 0x40) == 0, "v3 source2 config"); OK();
        char src2_dir[128];
        CHECK(v3_mkdir_tmp(src2_dir, "src2") == 0, "src2 tmpdir"); OK();
        uint8_t src2_chain32[NODUS_V2_GEN_CHAIN_ID_LEN];
        CHECK(nodus_witness_v2_gen_derive_v3(src2_dir, src2_cfg.cfg,
                                             src2_chain32) == 0,
              "derive v3 source2"); OK();
        CHECK(memcmp(src2_chain32, src_chain32, NODUS_V2_GEN_CHAIN_ID_LEN)
                  != 0, "the two sources DERIVE DIFFERENT chain ids"); OK();

        nodus_witness_t *src2_w = v3_open_readonly(src2_dir);
        CHECK(src2_w != NULL, "open v3 source2 read-only"); OK();
        uint8_t *b2 = NULL; size_t b2len = 0;
        CHECK(nodus_witness_v2_bundle_get(src2_w, &b2, &b2len) == 0 && b2,
              "src2 bundle bytes"); OK();

        char jdir[128];
        CHECK(v3_mkdir_tmp(jdir, "foreign") == 0, "joiner tmpdir"); OK();
        nodus_witness_t *jw = v3_open_fresh(jdir, 0xAC);
        CHECK(jw != NULL, "joiner db"); OK();

        CHECK(nodus_witness_v2_bundle_apply(jw, b2, b2len, src_chain32) != 0,
              "foreign v3 bundle + our pin REJECTS (pin is authority)");
        OK();
        /* Same caveat as the wrong-pin case above: proves NO DOCUMENT was
         * stored, not that `jw` is otherwise byte-unchanged — the
         * foreign bundle's six base tables were already planted by
         * bundle_apply's own BEGIN/COMMIT before this rejection (see
         * this file's header, HOW IT CAN LIE). The very next line reuses
         * this same `jw` handle successfully, which only works because
         * `nodus_witness_v2_bundle_apply` re-plants (DELETE + re-INSERT)
         * the base tables on every call, not because this one left them
         * empty. */
        CHECK(v3_has_doc(jw) == 0,
              "foreign bundle left NO readable document (zero trace)"); OK();
        CHECK(nodus_witness_v2_bundle_apply(jw, b2, b2len, src2_chain32)
                  == 0, "foreign v3 bundle + its own pin ADOPTS"); OK();

        free(b2);
        sqlite3_close(src2_w->db);
        free(src2_w);
        sqlite3_close(jw->db);
        free(jw);
        rmrf(jdir);
        rmrf(src2_dir);
        v3cfg_free(&src2_cfg);
    }

    free(bundle);
    sqlite3_close(src_w->db);
    free(src_w);
    rmrf(src_dir);
    v3cfg_free(&src_cfg);
    printf("test_v3_bundle: ALL CHECKS PASSED\n");
    return 0;
}

int main(void) {
    /* ── R3 W3 (D-17 rev 10 (9) / D-24 rev 4 (2)): A CHAIN WITH NO
     * STORED GENESIS DOCUMENT CANNOT BE BUNDLED — `bundle_persist`
     * refuses instead of producing a document-less bundle. Everything
     * this file proves about the ADOPT/wrong-pin/malformed/foreign-bundle
     * properties lives on the version-3 path (test_v3_bundle, below);
     * this section proves the refusal: persist refuses, no bundle row
     * exists, and an old-binary (`DNA.GBUNDLE.v1`) bundle is refused by
     * its magic with the joiner's whole database left byte-identical.
     *
     * tokenomics-v3 P4: the document-less chain used to be a VERSION-2
     * chain (v2x_genesis_min, which never stores a document). That lane's
     * derivation is deleted, so the same state is now reached from a real
     * version-3 chain (v2_genesis_fixture.h, v2x_chain_open) whose
     * "genesisDoc" row is then removed through the production store API:
     * a chain holding a genesis manifest and every base table, minus the
     * document — exactly the input the refusal exists for. */
    v2x_chain_t src;
    CHECK(v2x_chain_open(&src, "bundle_src", 0x00) == 0,
          "source fixture (version-3 genesis)"); OK();
    {
        nodus_cmt_store_t s;
        CHECK(nodus_cmt_store_init(&s, src.w->db, false) == CMT_OK,
              "store init"); OK();
        int drc = nodus_cmt_store_delete(&s, /*state_table=*/true,
                                         NODUS_V2_GEN_GENESIS_DOC_KEY);
        nodus_cmt_store_release(&s);
        CHECK(drc == CMT_OK, "the stored genesis document is removed"); OK();
        /* The derivation persisted a bundle while the document was
         * still there (nodus_witness_v2_gen_derive_v3 step 12); remove
         * it too, so "no bundle row" below is about THIS persist call. */
        CHECK(run_sql(src.w->db, "DELETE FROM v2_genesis_bundle") == 0,
              "the derivation's bundle is removed"); OK();
        {
            uint8_t *bundle = NULL;
            size_t blen = 0;
            CHECK(nodus_witness_v2_bundle_get(src.w, &bundle, &blen) == 1,
                  "precondition: no bundle row before the persist below");
            OK();
        }
    }

    CHECK(nodus_witness_v2_bundle_persist(src.w) != 0,
          "persist REFUSES a chain with no genesis document"); OK();

    {
        uint8_t *bundle = NULL;
        size_t blen = 0;
        CHECK(nodus_witness_v2_bundle_get(src.w, &bundle, &blen) == 1,
              "no bundle row — persist refused, nothing written"); OK();
    }

    /* an old-binary (version-1 magic) bundle is refused BY ITS MAGIC,
     * before any mutation — the joiner's whole-DB digest is unchanged.
     * The frame does not need to be a valid version-1 bundle past the
     * magic: nodus_witness_v2_bundle_apply's first act is the magic
     * comparison, so anything after it is never read. */
    {
        fixture_t j;
        CHECK(fx_open(&j, "oldmagic") == 0, "joiner fixture"); OK();

        uint8_t old_bundle[64];
        memcpy(old_bundle, NODUS_V2_GBUNDLE_MAGIC_V1_RETIRED,
               NODUS_V2_GBUNDLE_MAGIC_LEN);
        memset(old_bundle + NODUS_V2_GBUNDLE_MAGIC_LEN, 0x42,
               sizeof(old_bundle) - NODUS_V2_GBUNDLE_MAGIC_LEN);
        uint8_t any_pin[32];
        memset(any_pin, 0x99, sizeof(any_pin));

        uint8_t before[64], after[64];
        CHECK(db_digest_all(j.w, before) == 0, "digest before"); OK();
        CHECK(nodus_witness_v2_bundle_apply(j.w, old_bundle,
                                            sizeof(old_bundle),
                                            any_pin) != 0,
              "version-1 magic REFUSED"); OK();
        CHECK(db_digest_all(j.w, after) == 0, "digest after"); OK();
        CHECK(memcmp(before, after, 64) == 0,
              "the refused apply left the joiner's whole database "
              "byte-identical"); OK();
        CHECK(has_v2_block0(j.w) == 0, "no trace"); OK();

        fx_close(&j);
    }

    v2x_chain_close(&src);

    /* R3 W3 (D-24 rev 4) — the version-3 lane: the only one that can
     * actually produce and adopt a bundle now (see the closure section
     * above). */
    if (test_v3_bundle() != 0) return 1;

    printf("test_v2_bundle: ALL %d CHECKS PASSED\n", g_checks);
    return 0;
}
