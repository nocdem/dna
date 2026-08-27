/**
 * @file nodus/tests/test_v2_gen.c
 * @brief Ledger V2 O15J Faz 1 — the PURE-V2 genesis builder.
 *
 * Drives the REAL production functions (nodus_witness_v2_gen_derive,
 * _config_validate, _source_commit, _is_pure) over real chain databases.
 * No parallel builder, no re-implemented codec.
 *
 * Sections:
 *   §1  the §0 composition derives a COMPLETE genesis
 *   §2  determinism: independent twins, caller-order independence,
 *       config sensitivity
 *   §3  one explicit REJECT per red-team defect (L2-F1 … L2-F6, L1-F1)
 *   §4  fail-closed: a refused derivation leaves NOTHING behind
 *
 * ANTI-VACUITY. Each §3 assertion names the defect it kills and is
 * constructed so that removing the corresponding guard makes it FAIL.
 * Where a check is backstopped by a second, independent guard that is
 * stated too (L2-F2), the comment says so rather than claiming a
 * uniqueness the test does not have.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define _DEFAULT_SOURCE   /* mkdtemp under -std=c11 */

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_bundle.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_emission.h"  /* DNAC_BLOCKS_PER_YEAR,
                                              * DNAC_DECIMAL_UNIT (2C)   */
#include "witness/nodus_witness_v2_econ.h"   /* the committed econ band  */
#include "witness/nodus_witness_v2_gen.h"
#include "witness/nodus_witness_v2_schema.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/dnac.h"
#include "dnac/manifest_wire.h"
#include "dnac/validator.h"

#include "crypto/hash/qgp_sha3.h"

static int g_fail = 0;
static int g_checks = 0;
#define CHECK(cond, msg) do {                                            \
    g_checks++;                                                          \
    if (!(cond)) {                                                       \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__,         \
                __LINE__, (msg));                                        \
        g_fail = 1;                                                      \
    } } while (0)
#define OK() do { if (g_fail) return 1; } while (0)

/* ── the §0 composition ──────────────────────────────────────────────── */

#define TREASURY_RAW   93000000000000000ULL          /* 930,000,000 DNAC */
#define SPLIT3_EACH    31000000000000000ULL          /* 3 × = TREASURY   */
#define N_VAL          ((uint16_t)DNAC_COMMITTEE_SIZE)

/* ── helpers ─────────────────────────────────────────────────────────── */

static void rmrf(const char *dir) {
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    if (system(cmd) != 0) { /* best effort */ }
}

static int run_sql(sqlite3 *db, const char *sql) {
    char *e = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &e);
    if (e) sqlite3_free(e);
    return rc == SQLITE_OK ? 0 : -1;
}

static int64_t q1(sqlite3 *db, const char *sql) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -999;
    int64_t v = (sqlite3_step(st) == SQLITE_ROW)
                    ? sqlite3_column_int64(st, 0) : -999;
    sqlite3_finalize(st);
    return v;
}

static void hex_lower_fp(const uint8_t *src, size_t src_len, uint8_t *out129) {
    static const char hexd[] = "0123456789abcdef";
    uint8_t d[64];
    qgp_sha3_512(src, src_len, d);
    for (int i = 0; i < 64; i++) {
        out129[2 * i]     = (uint8_t)hexd[d[i] >> 4];
        out129[2 * i + 1] = (uint8_t)hexd[d[i] & 0x0F];
    }
    out129[128] = 0;
}

/* A whole-database LOGICAL digest: every user table plus sqlite_sequence
 * (the AUTOINCREMENT counters), rows in rowid order, each column's
 * storage type and bytes hashed. NOT a raw file hash — the SQLite file
 * image is not a deterministic representation of logical state.
 * Same construction as v2_genesis_fixture.h's v2x_db_digest; kept local
 * so this test compiles without the fixture header's other helpers. */
static int db_digest(sqlite3 *db, uint8_t out[64]) {
    sqlite3_stmt *ts = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT name FROM sqlite_master WHERE type='table' "
            "  AND name NOT LIKE 'sqlite_%' "
            "UNION ALL "
            "SELECT name FROM sqlite_master WHERE type='table' "
            "  AND name = 'sqlite_sequence' "
            "ORDER BY 1", -1, &ts, NULL) != SQLITE_OK)
        return -1;

    uint8_t acc[64];
    memset(acc, 0, sizeof(acc));
    int rc, ret = -1;
    while ((rc = sqlite3_step(ts)) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(ts, 0);
        if (!name) goto done;
        {
            uint8_t buf[64 + 128];
            size_t nl = strlen(name);
            if (nl > 127) goto done;
            memcpy(buf, acc, 64);
            memcpy(buf + 64, name, nl + 1);
            if (qgp_sha3_512(buf, 64 + nl + 1, acc) != 0) goto done;
        }
        char sql[256];
        snprintf(sql, sizeof(sql), "SELECT * FROM \"%s\" ORDER BY rowid",
                 name);
        sqlite3_stmt *rs = NULL;
        if (sqlite3_prepare_v2(db, sql, -1, &rs, NULL) != SQLITE_OK)
            goto done;
        int rrc;
        while ((rrc = sqlite3_step(rs)) == SQLITE_ROW) {
            int nc = sqlite3_column_count(rs);
            for (int c = 0; c < nc; c++) {
                int ty = sqlite3_column_type(rs, c);
                const void *p = NULL;
                int len = 0;
                int64_t iv = 0;
                if (ty == SQLITE_INTEGER) {
                    iv = sqlite3_column_int64(rs, c); p = &iv; len = 8;
                } else if (ty == SQLITE_TEXT || ty == SQLITE_BLOB) {
                    p = sqlite3_column_blob(rs, c);
                    len = sqlite3_column_bytes(rs, c);
                }
                uint8_t *buf = malloc(64 + 1 + (size_t)len);
                if (!buf) { sqlite3_finalize(rs); goto done; }
                memcpy(buf, acc, 64);
                buf[64] = (uint8_t)ty;
                if (p && len > 0) memcpy(buf + 65, p, (size_t)len);
                int hrc = qgp_sha3_512(buf, 65 + (size_t)len, acc);
                free(buf);
                if (hrc != 0) { sqlite3_finalize(rs); goto done; }
            }
        }
        sqlite3_finalize(rs);
        if (rrc != SQLITE_DONE) goto done;
    }
    if (rc != SQLITE_DONE) goto done;
    memcpy(out, acc, 64);
    ret = 0;
done:
    sqlite3_finalize(ts);
    return ret;
}

/* ── config construction ─────────────────────────────────────────────── */

typedef struct {
    nodus_v2_gen_config_t *cfg;
    nodus_v2_gen_alloc_t  *allocs;
} cfgbox_t;

static void cfg_free(cfgbox_t *b) {
    if (!b) return;
    free(b->cfg);
    free(b->allocs);
    b->cfg = NULL;
    b->allocs = NULL;
}

/**
 * The §0 composition: `n_alloc` treasury allocations totalling
 * TREASURY_RAW, plus 7 validators each bonding DNAC_SELF_STAKE_AMOUNT —
 * 10^17 raw in total, exactly DNAC_DEFAULT_TOTAL_SUPPLY.
 *
 * @param salt    perturbs every validator pubkey → a DIFFERENT chain.
 * @param reverse fills both arrays in DESCENDING key order, so a
 *                builder that did not sort would derive a different
 *                chain from the same set.
 */
static int cfg_make(cfgbox_t *b, uint8_t salt, uint32_t n_alloc,
                    int reverse) {
    memset(b, 0, sizeof(*b));
    if (n_alloc != 1 && n_alloc != 3) return -1;

    b->cfg = calloc(1, sizeof(*b->cfg));
    b->allocs = calloc(n_alloc, sizeof(*b->allocs));
    if (!b->cfg || !b->allocs) { cfg_free(b); return -1; }

    nodus_v2_gen_config_t *c = b->cfg;
    c->config_version     = NODUS_V2_GEN_CONFIG_VERSION;
    c->total_supply_raw   = DNAC_DEFAULT_TOTAL_SUPPLY;
    c->epoch_length       = (uint64_t)DNAC_EPOCH_LENGTH;
    /* Block 2C — the economic parameters. The three schedule constants
     * MUST equal the compiled ones or the builder refuses; the inflation
     * start is free, and 1 reproduces the pre-2C behaviour exactly (the
     * old builder could not express it, so every chain it derived took
     * the emission gate's 1ULL default). */
    c->blocks_per_year       = (uint64_t)DNAC_BLOCKS_PER_YEAR;
    c->decimal_unit          = (uint64_t)DNAC_DECIMAL_UNIT;
    c->inflation_start_block = 1ULL;
    c->claim_start_height = 0;
    c->claim_end_height   = UINT64_MAX;
    c->n_validators       = N_VAL;

    for (uint16_t k = 0; k < N_VAL; k++) {
        uint16_t i = reverse ? (uint16_t)(N_VAL - 1 - k) : k;
        nodus_v2_gen_validator_t *v = &c->validators[k];
        for (size_t bb = 0; bb < DNAC_PUBKEY_SIZE; bb++) {
            v->pubkey[bb] =
                (uint8_t)(0x11 * (i + 1) + (bb & 0x3F) + salt);
            v->unstake_destination_pubkey[bb] =
                (uint8_t)(v->pubkey[bb] ^ 0x5A);
        }
        hex_lower_fp(v->unstake_destination_pubkey, DNAC_PUBKEY_SIZE,
                     v->unstake_destination_fp);
        v->self_stake     = DNAC_SELF_STAKE_AMOUNT;
        v->commission_bps = (uint16_t)(100 * (i + 1));
    }

    for (uint32_t k = 0; k < n_alloc; k++) {
        uint32_t i = reverse ? (n_alloc - 1 - k) : k;
        nodus_v2_gen_alloc_t *a = &b->allocs[k];
        memset(a->source_id, 0, sizeof(a->source_id));
        a->source_id[0]  = (uint8_t)(0x30 + i);
        a->source_id[63] = (uint8_t)i;
        {
            uint8_t owner[DNAC_PUBKEY_SIZE];
            for (size_t bb = 0; bb < sizeof(owner); bb++)
                owner[bb] = (uint8_t)(0xA0 + i + (bb & 0x1F));
            /* the claim pipeline binds SHA3-512(claimant pubkey) to this
             * field byte-for-byte (nodus_witness_v2_claims.c:510-517) */
            qgp_sha3_512(owner, sizeof(owner), a->dest_binding);
        }
        a->amount = (n_alloc == 1) ? TREASURY_RAW : SPLIT3_EACH;
    }

    c->n_allocs = n_alloc;
    c->allocs   = b->allocs;
    return 0;
}

/* ── chain-db discovery / open ───────────────────────────────────────── */

/* 0 found, 1 none, -1 fault. */
static int find_chain(const char *dir, char out_path[600], uint8_t out16[16]) {
    DIR *d = opendir(dir);
    if (!d) return -1;
    struct dirent *e;
    int found = 1;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, "witness_", 8) != 0) continue;
        size_t len = strlen(e->d_name);
        if (len != 8 + 32 + 3 || strcmp(e->d_name + len - 3, ".db") != 0)
            continue;
        snprintf(out_path, 600, "%s/%s", dir, e->d_name);
        for (int i = 0; i < 16; i++) {
            unsigned bv = 0;
            if (sscanf(e->d_name + 8 + i * 2, "%2x", &bv) != 1) {
                closedir(d);
                return -1;
            }
            out16[i] = (uint8_t)bv;
        }
        found = 0;
        break;
    }
    closedir(d);
    return found;
}

/* Open the single chain DB in `dir`. Caller closes + frees. */
static nodus_witness_t *open_chain(const char *dir, char out_path[600]) {
    uint8_t id16[16];
    char path[600];
    if (find_chain(dir, path, id16) != 0) return NULL;
    if (out_path) memcpy(out_path, path, sizeof(path));
    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(w->data_path, sizeof(w->data_path), "%s", dir);
    if (nodus_witness_create_chain_db(w, id16) != 0) { free(w); return NULL; }

    /* O15J review R2-F2 — this used to say `w->v2_successor = 1;` here,
     * which MASKED the whole defect: production's role derivation runs
     * inside create_chain_db above and, before the fix, left the flag
     * FALSE for a pure-V2 chain (the probe matched only the ceremony's
     * DNA.LEGACY.TERM.v1 tag). Every consumer then took the legacy
     * branch — height 0 from the empty `blocks` table, a legacy GENESIS
     * transaction admissible into the V2 database, every V2 lane
     * refusing, and a halt at the first non-bootstrap epoch — while this
     * test reported PASS because it had overwritten the answer.
     *
     * The flag is now asserted, not assigned: if the production path
     * stops recognising a pure chain, this returns NULL and every
     * caller fails, which is exactly what should happen. */
    if (!w->v2_successor) {
        fprintf(stderr, "open_chain: production role derivation did NOT "
                        "recognise the pure-V2 chain at %s\n", path);
        if (w->db) sqlite3_close(w->db);
        free(w);
        return NULL;
    }
    return w;
}

static void close_chain(nodus_witness_t *w) {
    if (!w) return;
    if (w->db) { sqlite3_close(w->db); w->db = NULL; }
    free(w);
}

static int mkdir_tmp(char dir[128], const char *tag) {
    snprintf(dir, 128, "/tmp/test_v2_gen_%s_XXXXXX", tag);
    return mkdtemp(dir) ? 0 : -1;
}

/* ════════════════════════════════════════════════════════════════════
 * §1 — the §0 composition derives a COMPLETE genesis
 * ══════════════════════════════════════════════════════════════════ */

static int test_happy_path(void) {
    printf("§1 the §0 composition derives a complete pure-V2 genesis\n");

    cfgbox_t box;
    CHECK(cfg_make(&box, 0x00, 1, 0) == 0, "config");
    OK();

    /* the composition IS the design's: 9.3e16 + 7 × 1e15 == 10^17 */
    CHECK(TREASURY_RAW + 7ULL * DNAC_SELF_STAKE_AMOUNT ==
              DNAC_DEFAULT_TOTAL_SUPPLY,
          "treasury + 7 self-bonds == DNAC_DEFAULT_TOTAL_SUPPLY");

    char dir[128];
    CHECK(mkdir_tmp(dir, "happy") == 0, "tmpdir");
    OK();

    uint8_t chain32[32];
    memset(chain32, 0, sizeof(chain32));
    CHECK(nodus_witness_v2_gen_derive(dir, box.cfg, chain32) == 0,
          "derive succeeds");
    OK();

    char path[600];
    nodus_witness_t *w = open_chain(dir, path);
    CHECK(w != NULL, "the derived chain db opens");
    OK();

    CHECK(q1(w->db, "SELECT COUNT(*) FROM v2_blocks WHERE global_height = 0")
              == 1, "a genesis block is committed");
    CHECK(q1(w->db, "SELECT COUNT(*) FROM utxo_set") == 0,
          "NO spendable UTXO exists at genesis");
    CHECK(q1(w->db, "SELECT COALESCE(SUM(remaining),-1) FROM v2_dist_state")
              == (int64_t)TREASURY_RAW,
          "the claim reserve holds the whole treasury");
    CHECK(q1(w->db, "SELECT COALESCE(SUM(self_stake),0) FROM validators")
              == (int64_t)(7ULL * DNAC_SELF_STAKE_AMOUNT),
          "the validators hold exactly 7 × 10M bonded");
    CHECK(q1(w->db, "SELECT COUNT(*) FROM validators") == (int64_t)N_VAL,
          "seven validator rows");
    CHECK(q1(w->db, "SELECT genesis_supply FROM supply_tracking WHERE id=1")
              == (int64_t)DNAC_DEFAULT_TOTAL_SUPPLY,
          "supply_tracking carries the committed genesis supply");
    CHECK(q1(w->db, "SELECT value FROM validator_stats "
                    "WHERE key='active_count'") == (int64_t)N_VAL,
          "active_count == 7");
    CHECK(q1(w->db, "SELECT COUNT(*) FROM delegations") == 0 &&
          q1(w->db, "SELECT COUNT(*) FROM epoch_state") == 0,
          "delegations / epoch_state are EMPTY");
    /* Block 2C — chain_config_history is NO LONGER empty: it carries the
     * four committed economic parameters and NOTHING else. The exact
     * count is the assertion, so a fifth row (a future create_chain_db
     * seeding something of its own) fails here. */
    CHECK(q1(w->db, "SELECT COUNT(*) FROM chain_config_history") == 4,
          "chain_config_history holds exactly the 4 economic parameters");
    CHECK(q1(w->db, "SELECT COUNT(*) FROM validator_set_snapshots") == 2,
          "epoch 0 and epoch E snapshots are committed");

    /* the supply equation balances over the derived state */
    CHECK(nodus_witness_v2_supply_check(w) == 0,
          "the CORE conservation invariant holds at genesis");

    /* the committed manifest carries the pure-V2 binding */
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(w->db,
                  "SELECT manifest FROM v2_manifests "
                  "WHERE committed_height = 0 ORDER BY manifest_seq ASC "
                  "LIMIT 1", -1, &st, NULL) == SQLITE_OK, "manifest prep");
        CHECK(sqlite3_step(st) == SQLITE_ROW, "manifest row present");
        dna_gman_t m;
        CHECK(dna_gman_decode(sqlite3_column_blob(st, 0),
                              (size_t)sqlite3_column_bytes(st, 0), &m) == 0,
              "manifest decodes");
        sqlite3_finalize(st);

        CHECK(m.dist_present == 1, "the distribution section is present");
        CHECK(m.source_tag_len == NODUS_V2_GEN_SOURCE_TAG_LEN &&
                  memcmp(m.source_tag, NODUS_V2_GEN_SOURCE_TAG,
                         NODUS_V2_GEN_SOURCE_TAG_LEN) == 0,
              "source_tag is DNA.GENESIS.v1 — NOT a legacy terminal tag");
        CHECK(m.source_commit_len == NODUS_V2_GEN_SRCCOMMIT_LEN,
              "source_commit is a 64-byte digest");
        uint8_t expect[NODUS_V2_GEN_SRCCOMMIT_LEN];
        CHECK(nodus_witness_v2_gen_source_commit(box.cfg, expect) == 0,
              "source_commit recomputes");
        CHECK(memcmp(m.source_commit, expect,
                     NODUS_V2_GEN_SRCCOMMIT_LEN) == 0,
              "the manifest binds SHA3-512(canonical config bytes)");
        CHECK(m.genesis_supply_raw == DNAC_DEFAULT_TOTAL_SUPPLY,
              "the manifest commits the real genesis supply (not 0)");
        CHECK(m.total_claimable == TREASURY_RAW && m.leaf_count == 1,
              "total_claimable and leaf_count match the allocations");
        /* L2-F3: the window that actually landed */
        CHECK(m.claim_start_height == 0 &&
                  m.claim_end_height == UINT64_MAX,
              "the committed claim window is the pinned [0, UINT64_MAX]");
        CHECK(m.conv_numerator == 1 && m.conv_denominator == 1 &&
                  m.rounding_mode == DNA_DISTROUND_FLOOR &&
                  m.excluded_amount == 0,
              "1:1 FLOOR conversion, nothing excluded");
    }

    CHECK(nodus_witness_v2_gen_is_pure(path) == 1,
          "the pure-V2 probe recognises the derived chain");

    close_chain(w);

    /* idempotency: a second derive over the same data_path is a no-op */
    {
        uint8_t again[32];
        memset(again, 0xEE, sizeof(again));
        CHECK(nodus_witness_v2_gen_derive(dir, box.cfg, again) == 0,
              "re-derivation returns success");
        char p2[600];
        uint8_t id2[16];
        CHECK(find_chain(dir, p2, id2) == 0 && strcmp(p2, path) == 0,
              "and left the SAME single chain db (no second chain)");
    }

    rmrf(dir);
    cfg_free(&box);
    OK();
    printf("  ok: complete genesis, reserve, bonds, manifest, supply gate\n");
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * §2 — determinism
 * ══════════════════════════════════════════════════════════════════ */

/* Derive `box` into a fresh dir and report chain id, genesis BlockID and
 * the whole-database logical digest. */
static int derive_probe(cfgbox_t *box, const char *tag, char dir[128],
                        uint8_t chain32[32], uint8_t gid[64],
                        uint8_t digest[64]) {
    if (mkdir_tmp(dir, tag) != 0) return -1;
    if (nodus_witness_v2_gen_derive(dir, box->cfg, chain32) != 0) return -1;
    char path[600];
    nodus_witness_t *w = open_chain(dir, path);
    if (!w) return -1;
    int rc = -1;
    do {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT block_id FROM v2_blocks WHERE global_height = 0",
                -1, &st, NULL) != SQLITE_OK) break;
        int srow = sqlite3_step(st);
        if (srow != SQLITE_ROW || sqlite3_column_bytes(st, 0) != 64) {
            sqlite3_finalize(st);
            break;
        }
        memcpy(gid, sqlite3_column_blob(st, 0), 64);
        sqlite3_finalize(st);
        if (db_digest(w->db, digest) != 0) break;
        rc = 0;
    } while (0);
    close_chain(w);
    return rc;
}

static int test_determinism(void) {
    printf("§2 determinism twins, caller-order independence, sensitivity\n");

    cfgbox_t a, b, r, s;
    CHECK(cfg_make(&a, 0x00, 3, 0) == 0, "config a");
    CHECK(cfg_make(&b, 0x00, 3, 0) == 0, "config b (independent, equal)");
    CHECK(cfg_make(&r, 0x00, 3, 1) == 0, "config r (same set, REVERSED)");
    CHECK(cfg_make(&s, 0x01, 3, 0) == 0, "config s (one salted pubkey set)");
    OK();

    char da[128], db_[128], dr[128], ds[128];
    uint8_t ca[32], cb[32], cr[32], cs[32];
    uint8_t ga[64], gb[64], gr[64], gs[64];
    uint8_t ha[64], hb[64], hr[64], hs[64];

    CHECK(derive_probe(&a, "det_a", da, ca, ga, ha) == 0, "derive a");
    CHECK(derive_probe(&b, "det_b", db_, cb, gb, hb) == 0, "derive b");
    CHECK(derive_probe(&r, "det_r", dr, cr, gr, hr) == 0, "derive r");
    CHECK(derive_probe(&s, "det_s", ds, cs, gs, hs) == 0, "derive s");
    OK();

    CHECK(memcmp(ca, cb, 32) == 0,
          "TWIN: two independent derivations from equal configs produce "
          "the SAME chain id");
    CHECK(memcmp(ga, gb, 64) == 0,
          "TWIN: … the SAME genesis BlockID");
    CHECK(memcmp(ha, hb, 64) == 0,
          "TWIN: … and a byte-identical whole-database logical digest");

    /* THE SORTING KILL-ASSERTION. `r` holds the identical validator and
     * allocation SET, filled into the config arrays in the opposite
     * order. A builder that hashed or inserted in caller order would
     * derive a different chain id AND a different rowid layout; the
     * canonical pubkey-ASC / source_id-ASC sort is what makes these
     * equal. */
    CHECK(memcmp(ca, cr, 32) == 0,
          "ORDER: reversing the caller's arrays derives the SAME chain id");
    CHECK(memcmp(ha, hr, 64) == 0,
          "ORDER: … and the SAME whole-database digest (rowid layout too)");

    /* SENSITIVITY: a different validator set is a different chain. */
    CHECK(memcmp(ca, cs, 32) != 0,
          "SENSITIVITY: a different validator set derives a DIFFERENT "
          "chain id");
    CHECK(memcmp(ga, gs, 64) != 0, "SENSITIVITY: … and BlockID");

    rmrf(da); rmrf(db_); rmrf(dr); rmrf(ds);
    cfg_free(&a); cfg_free(&b); cfg_free(&r); cfg_free(&s);
    OK();
    printf("  ok: twins identical, order-independent, set-sensitive\n");
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * §3 — one explicit REJECT per red-team defect
 * ══════════════════════════════════════════════════════════════════ */

static int test_defect_L2F6(void) {
    printf("§3.1 L2-F6 — the legacy genesis rules P.1 / P.2 / P.3\n");
    cfgbox_t c;

    /* Rule P.1 — EXACT initial validator count.
     * KILL: drop the n_validators != DNAC_COMMITTEE_SIZE check and a
     * 6-validator config derives a chain the legacy rule forbids. */
    CHECK(cfg_make(&c, 0, 1, 0) == 0, "cfg");
    OK();
    c.cfg->n_validators = (uint16_t)(N_VAL - 1);
    /* keep the arithmetic honest so ONLY P.1 can reject: put the removed
     * validator's bond into the treasury */
    c.allocs[0].amount = TREASURY_RAW + DNAC_SELF_STAKE_AMOUNT;
    CHECK(nodus_witness_v2_gen_config_validate(c.cfg) != 0,
          "P.1: six validators REJECT (the supply still balances)");
    cfg_free(&c);

    /* Rule P.2 — the supply sum. Both directions. */
    CHECK(cfg_make(&c, 0, 1, 0) == 0, "cfg");
    OK();
    c.allocs[0].amount = TREASURY_RAW + 1;      /* over-allocation */
    CHECK(nodus_witness_v2_gen_config_validate(c.cfg) != 0,
          "P.2: over-allocation by 1 raw unit REJECTS");
    c.allocs[0].amount = TREASURY_RAW - 1;      /* under-allocation */
    CHECK(nodus_witness_v2_gen_config_validate(c.cfg) != 0,
          "P.2: under-allocation by 1 raw unit REJECTS");
    c.allocs[0].amount = TREASURY_RAW;
    CHECK(nodus_witness_v2_gen_config_validate(c.cfg) == 0,
          "P.2: the exact composition is ACCEPTED (positive control)");
    cfg_free(&c);

    /* a self_stake that is not the exact bond */
    CHECK(cfg_make(&c, 0, 1, 0) == 0, "cfg");
    OK();
    c.cfg->validators[3].self_stake = DNAC_SELF_STAKE_AMOUNT - 1;
    c.allocs[0].amount = TREASURY_RAW + 1;      /* still sums to 10^17 */
    CHECK(nodus_witness_v2_gen_config_validate(c.cfg) != 0,
          "a non-exact self-bond REJECTS even when the total balances");
    cfg_free(&c);

    /* Rule P.3 — pairwise-distinct pubkeys.
     * KILL: drop the O(N²) loop and this config reaches the DB layer,
     * where the outcome would depend on a storage-layer PK collision
     * rather than on a stated genesis rule. */
    CHECK(cfg_make(&c, 0, 1, 0) == 0, "cfg");
    OK();
    memcpy(c.cfg->validators[5].pubkey, c.cfg->validators[2].pubkey,
           DNAC_PUBKEY_SIZE);
    CHECK(nodus_witness_v2_gen_config_validate(c.cfg) != 0,
          "P.3: a duplicate validator pubkey REJECTS");
    cfg_free(&c);

    OK();
    printf("  ok: P.1 / P.2 / P.3 all reject\n");
    return 0;
}

static int test_defect_L2F4(void) {
    printf("§3.2 L2-F4 — a graduation-malformed validator row\n");
    cfgbox_t c;

    /* An ALL-ZERO fingerprint: the validator merkle leaf legally hashes
     * 128 zero bytes, so genesis would succeed and the chain would then
     * FAULT -2 at its first RETIRING graduation — a deterministic halt.
     * KILL: remove the nodus_witness_v2_epoch_val_rec_ok call and this
     * config derives a complete, permanently-doomed chain. */
    CHECK(cfg_make(&c, 0, 1, 0) == 0, "cfg");
    OK();
    memset(c.cfg->validators[0].unstake_destination_fp, 0,
           DNAC_FINGERPRINT_SIZE);
    CHECK(nodus_witness_v2_gen_config_validate(c.cfg) != 0,
          "an all-zero unstake_destination_fp REJECTS");
    cfg_free(&c);

    /* a SHORT fingerprint (NUL at 64 instead of 128) */
    CHECK(cfg_make(&c, 0, 1, 0) == 0, "cfg");
    OK();
    memset(c.cfg->validators[1].unstake_destination_fp + 64, 0, 65);
    CHECK(nodus_witness_v2_gen_config_validate(c.cfg) != 0,
          "a short unstake_destination_fp REJECTS");
    cfg_free(&c);

    /* UPPERCASE hex — accepted by a naive hex check, refused by the
     * graduation predicate (which demands lowercase) */
    CHECK(cfg_make(&c, 0, 1, 0) == 0, "cfg");
    OK();
    /* set an explicit uppercase digit rather than case-flipping whatever
     * the digest happened to produce — the rejection must not depend on
     * the content of a hash */
    c.cfg->validators[2].unstake_destination_fp[7] = 'A';
    CHECK(nodus_witness_v2_gen_config_validate(c.cfg) != 0,
          "an UPPERCASE-hex character in the fingerprint REJECTS");
    cfg_free(&c);

    /* a missing NUL terminator at index 128 */
    CHECK(cfg_make(&c, 0, 1, 0) == 0, "cfg");
    OK();
    c.cfg->validators[4].unstake_destination_fp[128] = 'a';
    CHECK(nodus_witness_v2_gen_config_validate(c.cfg) != 0,
          "an unterminated fingerprint REJECTS");
    cfg_free(&c);

    /* an out-of-range commission */
    CHECK(cfg_make(&c, 0, 1, 0) == 0, "cfg");
    OK();
    c.cfg->validators[6].commission_bps =
        (uint16_t)(DNAC_COMMISSION_BPS_MAX + 1);
    CHECK(nodus_witness_v2_gen_config_validate(c.cfg) != 0,
          "commission_bps above the maximum REJECTS");
    cfg_free(&c);

    OK();
    printf("  ok: every graduation-malformed row is refused at config time\n");
    return 0;
}

static int test_defect_L2F3(void) {
    printf("§3.3 L2-F3 — the claim height window\n");
    cfgbox_t c;

    /* [0,0]: the codec accepts it (start <= end), the supply equation
     * still balances (the value counts as unclaimed distribution), and
     * the treasury is stranded FOREVER — no block height satisfies the
     * gate, because genesis is height 0 and carries no claims.
     * KILL: remove the window pin and this derives a dead chain. */
    CHECK(cfg_make(&c, 0, 1, 0) == 0, "cfg");
    OK();
    c.cfg->claim_end_height = 0;
    CHECK(nodus_witness_v2_gen_config_validate(c.cfg) != 0,
          "a [0,0] claim window REJECTS");

    /* a merely NARROW window: satisfiable, but under DNA_POSTDL_RETAIN
     * anything unclaimed at expiry is stranded just the same */
    c.cfg->claim_end_height = 1000;
    CHECK(nodus_witness_v2_gen_config_validate(c.cfg) != 0,
          "a narrow [0,1000] claim window REJECTS");

    /* a late START strands every claim before it and is equally refused */
    c.cfg->claim_start_height = 5;
    c.cfg->claim_end_height   = UINT64_MAX;
    CHECK(nodus_witness_v2_gen_config_validate(c.cfg) != 0,
          "a non-zero claim_start_height REJECTS");

    c.cfg->claim_start_height = 0;
    CHECK(nodus_witness_v2_gen_config_validate(c.cfg) == 0,
          "[0, UINT64_MAX] is ACCEPTED (positive control)");
    cfg_free(&c);

    OK();
    printf("  ok: only the pinned window derives\n");
    return 0;
}

static int test_defect_L2F2(void) {
    printf("§3.4 L2-F2 — total_claimable is tied to the leaves\n");

    /* PART A — the guard itself, over the exact leaf set the builder
     * hands it. dna_dist_check_totals had ONE production caller and it
     * was inside the seam step this builder replaces; this proves the
     * call is load-bearing on the leaf set, not merely present. */
    {
        dna_dist_leaf_t L[3];
        memset(L, 0, sizeof(L));
        for (int i = 0; i < 3; i++) {
            L[i].leaf_version  = DNA_DIST_VERSION;
            L[i].source_id_len = (uint16_t)NODUS_V2_GEN_SRCID_LEN;
            L[i].source_id[0]  = (uint8_t)(0x30 + i);
            L[i].source_id[63] = (uint8_t)i;
            L[i].source_amount = SPLIT3_EACH;
        }
        CHECK(dna_dist_check_totals(L, 3, 1, 1, DNA_DISTROUND_FLOOR,
                                    TREASURY_RAW) == 0,
              "the leaf set totals the treasury (positive control)");
        CHECK(dna_dist_check_totals(L, 3, 1, 1, DNA_DISTROUND_FLOOR,
                                    TREASURY_RAW + 1) != 0,
              "a total_claimable one raw unit HIGH is caught");
        CHECK(dna_dist_check_totals(L, 3, 1, 1, DNA_DISTROUND_FLOOR,
                                    TREASURY_RAW - 1) != 0,
              "a total_claimable one raw unit LOW is caught");
        /* a zero-amount leaf can never carry claimable value */
        L[1].source_amount = 0;
        CHECK(dna_dist_check_totals(L, 3, 1, 1, DNA_DISTROUND_FLOOR,
                                    SPLIT3_EACH * 2) != 0,
              "a zero-amount leaf is refused, not silently summed as 0");
    }

    /* PART B — through the builder. A leaf set that does not total the
     * supply-derived claimable REJECTS.
     *
     * HONEST ANTI-VACUITY NOTE (rewritten after review R1):
     *
     * PART B's input is ALSO caught by Rule P.2 (§3.1), so deleting the
     * dna_dist_check_totals call would not fail this assertion. That is
     * a real limitation and it is stated rather than papered over.
     *
     * R1 found the counterexample the first version of this note
     * denied: a ZERO-AMOUNT leaf passed P.2 (it contributes nothing to
     * the sum) and passed the duplicate check (dna_dist_leaf_cmp
     * compares source_id ONLY), and was rejected solely inside
     * check_totals → dna_dist_converted. That gap is now closed by an
     * explicit `amount < 1` guard in gen_plan_build, covered by §3.7
     * below — an earlier, clearer refusal than a conversion-time one.
     *
     * With that guard in place and the manifest's committed 1:1 FLOOR
     * conversion, check_totals and P.2 are now genuinely mutually
     * redundant on this path: neither has an input the other misses.
     * The call is therefore DEFENCE IN DEPTH, not a uniquely-triggered
     * check, and it earns its place only against a future conversion
     * ratio that is not 1:1 — where rounding and overflow become
     * reachable and P.2 alone would not see them. Labelled honestly so
     * a later reader does not mistake PART B for a kill it is not. */
    {
        cfgbox_t c;
        CHECK(cfg_make(&c, 0, 3, 0) == 0, "cfg");
        OK();
        c.allocs[2].amount = SPLIT3_EACH - 1000;
        CHECK(nodus_witness_v2_gen_config_validate(c.cfg) != 0,
              "a leaf set that under-totals the claimable REJECTS");
        c.allocs[2].amount = SPLIT3_EACH;
        CHECK(nodus_witness_v2_gen_config_validate(c.cfg) == 0,
              "restored (positive control)");

        /* a duplicate source_id would collide two claim identities */
        memcpy(c.allocs[1].source_id, c.allocs[0].source_id,
               NODUS_V2_GEN_SRCID_LEN);
        CHECK(nodus_witness_v2_gen_config_validate(c.cfg) != 0,
              "a duplicate allocation source_id REJECTS");
        cfg_free(&c);
    }

    OK();
    printf("  ok: the committed total_claimable cannot lie about the "
           "leaves\n");
    return 0;
}

static int test_defect_L2F1(void) {
    printf("§3.5 L2-F1 — an absent supply row is a FAILURE, not a skip\n");

    /* ── the scoping half: a legacy / pre-genesis DB is UNCHANGED ──── */
    {
        char dir[128];
        CHECK(mkdir_tmp(dir, "f1_legacy") == 0, "tmpdir");
        OK();
        nodus_witness_t *w = calloc(1, sizeof(*w));
        CHECK(w != NULL, "handle");
        OK();
        w->cached_committee_epoch_start = UINT64_MAX;
        snprintf(w->data_path, sizeof(w->data_path), "%s", dir);
        uint8_t id16[16];
        memset(id16, 0x5A, sizeof(id16));
        CHECK(nodus_witness_create_chain_db(w, id16) == 0, "legacy db");
        CHECK(q1(w->db, "SELECT COUNT(*) FROM supply_tracking") == 0,
              "a fresh db has NO supply row (pre-genesis)");
        CHECK(nodus_witness_v2_supply_check(w) == 0,
              "SCOPE: a db with no v2_blocks table still returns 0 — the "
              "legitimate legacy pre-genesis path is NOT weakened");

        /* v2_blocks now EXISTS but holds no genesis: still pre-genesis */
        CHECK(nodus_witness_db_migrate_v2s12(w) == 0, "migrate to S12");
        CHECK(q1(w->db, "SELECT COUNT(*) FROM v2_blocks") == 0,
              "no block committed");
        CHECK(nodus_witness_v2_supply_check(w) == 0,
              "SCOPE: v2_blocks present but empty still returns 0");
        close_chain(w);
        rmrf(dir);
    }

    /* ── the defect half: a chain WITH a V2 genesis must fail ──────── */
    {
        cfgbox_t c;
        CHECK(cfg_make(&c, 0, 1, 0) == 0, "cfg");
        char dir[128];
        CHECK(mkdir_tmp(dir, "f1_pure") == 0, "tmpdir");
        OK();
        CHECK(nodus_witness_v2_gen_derive(dir, c.cfg, NULL) == 0, "derive");
        OK();
        nodus_witness_t *w = open_chain(dir, NULL);
        CHECK(w != NULL, "open");
        OK();
        CHECK(nodus_witness_v2_supply_check(w) == 0,
              "the gate PASSES on the intact chain (positive control)");

        /* Delete the row the whole invariant is evaluated against.
         * KILL: with the old unconditional `return 0` this check
         * returns 0 and the assertion below FAILS — the invariant was
         * skipped, not failed, for the life of the chain. */
        CHECK(run_sql(w->db, "DELETE FROM supply_tracking") == 0, "delete");
        CHECK(q1(w->db, "SELECT COUNT(*) FROM supply_tracking") == 0,
              "the row is gone");
        CHECK(nodus_witness_v2_supply_check(w) != 0,
              "an absent supply row on a chain that HAS a V2 genesis "
              "FAILS CLOSED (it is no longer silently skipped)");
        close_chain(w);
        rmrf(dir);
        cfg_free(&c);
    }

    OK();
    printf("  ok: absent row fails post-genesis, unchanged pre-genesis\n");
    return 0;
}

static int test_defect_L1F1(void) {
    printf("§3.6 L1-F1 — validator_stats travels in the genesis bundle\n");

    cfgbox_t c;
    CHECK(cfg_make(&c, 0, 1, 0) == 0, "cfg");
    char sdir[128], jdir[128];
    CHECK(mkdir_tmp(sdir, "l1f1_src") == 0, "src dir");
    CHECK(mkdir_tmp(jdir, "l1f1_join") == 0, "joiner dir");
    OK();
    CHECK(nodus_witness_v2_gen_derive(sdir, c.cfg, NULL) == 0, "derive");
    OK();

    nodus_witness_t *src = open_chain(sdir, NULL);
    CHECK(src != NULL, "open source");
    OK();

    uint8_t *bundle = NULL;
    size_t blen = 0;
    CHECK(nodus_witness_v2_bundle_get(src, &bundle, &blen) == 0 &&
              bundle && blen > 0,
          "the derivation persisted a genesis bundle");
    OK();

    uint8_t pin[64];
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(src->db,
                  "SELECT block_id FROM v2_blocks WHERE global_height = 0",
                  -1, &st, NULL) == SQLITE_OK, "pin prep");
        CHECK(sqlite3_step(st) == SQLITE_ROW &&
                  sqlite3_column_bytes(st, 0) == 64, "pin row");
        memcpy(pin, sqlite3_column_blob(st, 0), 64);
        sqlite3_finalize(st);
    }
    OK();

    /* a fresh joiner, exactly as nodus_witness_v2_join.c builds one */
    nodus_witness_t *j = calloc(1, sizeof(*j));
    CHECK(j != NULL, "joiner handle");
    OK();
    j->cached_committee_epoch_start = UINT64_MAX;
    snprintf(j->data_path, sizeof(j->data_path), "%s", jdir);
    {
        uint8_t jid16[16];
        memset(jid16, 0xAA, sizeof(jid16));
        CHECK(nodus_witness_create_chain_db(j, jid16) == 0, "joiner db");
    }
    j->v2_successor = 1;
    CHECK(nodus_witness_db_migrate_v2s12(j) == 0, "joiner S12");
    CHECK(nodus_chain_config_db_migrate(j) == 0, "joiner chain_config");
    CHECK(q1(j->db, "SELECT value FROM validator_stats "
                    "WHERE key='active_count'") == 0,
          "the joiner starts with the create_chain_db seed of 0");
    OK();

    CHECK(nodus_witness_v2_bundle_apply(j, bundle, blen, pin) == 0,
          "the joiner adopts the bundle against the pin");
    OK();

    /* THE KILL. With validator_stats absent from BUNDLE_TABLES the
     * joiner keeps its seeded 0 while its genesis still matches the pin
     * byte-for-byte — a SILENT divergence that surfaces as a -2 fault
     * at the first graduation (v2ep_active_count_dec refuses a counter
     * that cannot absorb a decrement). */
    CHECK(q1(j->db, "SELECT value FROM validator_stats "
                    "WHERE key='active_count'") == (int64_t)N_VAL,
          "the joiner's active_count equals the producer's 7");
    CHECK(q1(j->db, "SELECT COUNT(*) FROM validators") == (int64_t)N_VAL,
          "and it carries every validator row");

    /* Block 2C — THE JOINER HOLE, closed. A joiner never runs the
     * builder, so the config→source_commit binding cannot protect it:
     * before 2C a node built with a different DNAC_BLOCKS_PER_YEAR joined
     * THIS chain cleanly and then minted a different amount, with nothing
     * visible on the wire. Only a READABLE COMMITTED value catches that,
     * and it only works if the band travels in the bundle.
     * MUTANT KILLED: drop "chain_config_history" from BUNDLE_TABLES
     * (nodus_witness_v2_bundle.c:47). */
    {
        nodus_v2_econ_params_t jp;
        CHECK(nodus_witness_v2_econ_params_load(j, &jp) == 0 && jp.present,
              "the joiner adopted the committed economic band");
        CHECK(jp.blocks_per_year == (uint64_t)DNAC_BLOCKS_PER_YEAR &&
              jp.decimal_unit    == (uint64_t)DNAC_DECIMAL_UNIT &&
              jp.epoch_length    == (uint64_t)DNAC_EPOCH_LENGTH,
              "carrying the PRODUCER's economic values, not its own "
              "compiled defaults");
        CHECK(nodus_chain_config_get_u64(
                  j, (uint8_t)DNAC_CFG_INFLATION_START_BLOCK, 0,
                  UINT64_MAX) == 1ULL,
              "and the inflation start arrived as committed state");
    }
    CHECK(q1(j->db, "SELECT COUNT(*) FROM v2_blocks WHERE global_height=0")
              == 1, "the joiner derived a genesis");

    /* the adopted genesis is byte-identical to the producer's */
    {
        uint8_t jid[64];
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(j->db,
                  "SELECT block_id FROM v2_blocks WHERE global_height = 0",
                  -1, &st, NULL) == SQLITE_OK, "jid prep");
        CHECK(sqlite3_step(st) == SQLITE_ROW &&
                  sqlite3_column_bytes(st, 0) == 64, "jid row");
        memcpy(jid, sqlite3_column_blob(st, 0), 64);
        sqlite3_finalize(st);
        CHECK(memcmp(jid, pin, 64) == 0,
              "the joiner re-derived the IDENTICAL genesis BlockID");
    }

    free(bundle);
    close_chain(j);
    close_chain(src);
    rmrf(sdir);
    rmrf(jdir);
    cfg_free(&c);
    OK();
    printf("  ok: the sixth base table crosses to the joiner\n");
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * §3.7 — review R1-F4: a zero-amount allocation leaf
 *
 * The gap R1 found: a leaf with amount 0 passed Rule P.2 (it adds
 * nothing to the sum) AND passed the duplicate check (dna_dist_leaf_cmp
 * compares source_id only, shared/dnac/manifest_wire.c:331-339), so
 * nodus_witness_v2_gen_config_validate answered YES for a config that
 * nodus_witness_v2_gen_derive then refused deeper in, inside
 * dna_dist_leaf_hash. An oracle that disagrees with the thing it is an
 * oracle for is worse than no oracle.
 *
 * ANTI-VACUITY STATUS — MEASURED, NOT ASSERTED. Three mutation runs:
 *   M1: `amount < 1` guard disabled          → SURVIVED
 *   M2: dna_dist_check_totals call disabled  → SURVIVED
 *   M3: BOTH disabled together               → KILLED (rc 1, this exact
 *       assertion: "a zero-amount leaf REJECTS even though the totals
 *       balance")
 *
 * So the two guards are MUTUALLY REDUNDANT on this input and neither
 * dies alone — the same shape the O12 M8 and O13 M12 campaigns hit,
 * where a doubly-defended property needs a COMPOUND mutant. There is
 * no third, hidden rejector; an earlier version of this note claimed
 * one existed, and it was wrong because M1 and M2 were only ever run
 * in isolation.
 *
 * What this section therefore proves: the PAIR is load-bearing. Delete
 * either guard and the property still holds; delete both and it does
 * not. That is a real kill, stated at the granularity at which it is
 * true.
 *
 * R1-F4's claim that config_validate ACCEPTS a zero-amount leaf is
 * REFUTED: it rejects, via check_totals → dna_dist_converted even
 * before the explicit guard was added.
 * ══════════════════════════════════════════════════════════════════ */
static int test_zero_amount_leaf(void) {
    printf("§3.7 R1-F4 — a zero-amount allocation leaf REJECTS\n");

    cfgbox_t c;
    CHECK(cfg_make(&c, 0, 3, 0) == 0, "cfg"); OK();

    /* Move leaf[2]'s whole amount onto leaf[1] and zero leaf[2]. The sum
     * is UNCHANGED, so Rule P.2 and dna_dist_check_totals both still
     * balance exactly — only the amount bound can fire. */
    c.allocs[1].amount += c.allocs[2].amount;
    c.allocs[2].amount  = 0;
    CHECK(nodus_witness_v2_gen_config_validate(c.cfg) != 0,
          "a zero-amount leaf REJECTS even though the totals balance");
    OK();

    /* Positive control: restore a non-zero split and it validates, so
     * the rejection above is the amount and not the redistribution. */
    c.allocs[2].amount  = 1;
    c.allocs[1].amount -= 1;
    CHECK(nodus_witness_v2_gen_config_validate(c.cfg) == 0,
          "the same shape with amount 1 validates"); OK();

    cfg_free(&c);
    printf("  ok: config_validate no longer accepts what derive refuses\n");
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * §4 — fail-closed
 * ══════════════════════════════════════════════════════════════════ */

/* Does `dir` hold any witness db or a leftover scratch dir? */
static int dir_is_clean(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return -1;
    struct dirent *e;
    int clean = 1;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        clean = 0;
        break;
    }
    closedir(d);
    return clean;
}

static int test_fail_closed(void) {
    printf("§4 a refused derivation leaves NOTHING behind\n");

    /* a config that fails the exact-count rule */
    {
        cfgbox_t c;
        CHECK(cfg_make(&c, 0, 1, 0) == 0, "cfg");
        char dir[128];
        CHECK(mkdir_tmp(dir, "fc_p1") == 0, "tmpdir");
        OK();
        c.cfg->n_validators = (uint16_t)(N_VAL - 1);
        c.allocs[0].amount = TREASURY_RAW + DNAC_SELF_STAKE_AMOUNT;
        CHECK(nodus_witness_v2_gen_derive(dir, c.cfg, NULL) != 0,
              "the derivation is REFUSED");
        CHECK(dir_is_clean(dir) == 1,
              "and the data path is untouched — no chain db, no scratch");
        rmrf(dir);
        cfg_free(&c);
    }

    /* a build whose epoch length disagrees with the config.
     * The config commits DNAC_EPOCH_LENGTH because that value reaches
     * the genesis BlockID through the epoch-keyed vset snapshots; a
     * build that disagrees must refuse LOUDLY instead of deriving a
     * silently different chain id from the same config bytes. */
    {
        cfgbox_t c;
        CHECK(cfg_make(&c, 0, 1, 0) == 0, "cfg");
        char dir[128];
        CHECK(mkdir_tmp(dir, "fc_epoch") == 0, "tmpdir");
        OK();
        c.cfg->epoch_length = (uint64_t)DNAC_EPOCH_LENGTH + 1;
        CHECK(nodus_witness_v2_gen_derive(dir, c.cfg, NULL) != 0,
              "an epoch_length this build cannot honour is REFUSED");
        CHECK(dir_is_clean(dir) == 1, "nothing left behind");
        rmrf(dir);
        cfg_free(&c);
    }

    /* an unknown config version */
    {
        cfgbox_t c;
        CHECK(cfg_make(&c, 0, 1, 0) == 0, "cfg");
        OK();
        c.cfg->config_version = NODUS_V2_GEN_CONFIG_VERSION + 1;
        CHECK(nodus_witness_v2_gen_config_validate(c.cfg) != 0,
              "an unknown config_version REJECTS");
        cfg_free(&c);
    }

    /* zero allocations: a distribution with no leaves has no identity */
    {
        cfgbox_t c;
        CHECK(cfg_make(&c, 0, 1, 0) == 0, "cfg");
        OK();
        c.cfg->n_allocs = 0;
        CHECK(nodus_witness_v2_gen_config_validate(c.cfg) != 0,
              "zero allocations REJECT");
        cfg_free(&c);
    }

    /* the canonical encoding is stable and order-independent */
    {
        cfgbox_t f, r;
        CHECK(cfg_make(&f, 0, 3, 0) == 0, "cfg forward");
        CHECK(cfg_make(&r, 0, 3, 1) == 0, "cfg reversed");
        OK();
        uint8_t *bf = NULL, *br = NULL;
        size_t lf = 0, lr = 0;
        CHECK(nodus_witness_v2_gen_config_encode(f.cfg, &bf, &lf) == 0 &&
              nodus_witness_v2_gen_config_encode(r.cfg, &br, &lr) == 0,
              "both configs encode");
        CHECK(lf == lr && bf && br && memcmp(bf, br, lf) == 0,
              "the canonical encoding is byte-identical regardless of the "
              "caller's array order");
        /* and it is not trivially empty */
        CHECK(lf > NODUS_V2_GEN_CFG_TAG_LEN + 30, "the encoding is real");
        free(bf);
        free(br);
        cfg_free(&f);
        cfg_free(&r);
    }

    OK();
    printf("  ok: every refusal is total; the encoding is canonical\n");
    return 0;
}

/* ════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("=== Ledger V2 O15J Faz 1 — the pure-V2 genesis builder ===\n\n");
    if (test_happy_path())    return 1;
    if (test_determinism())   return 1;
    if (test_defect_L2F6())   return 1;
    if (test_defect_L2F4())   return 1;
    if (test_defect_L2F3())   return 1;
    if (test_defect_L2F2())   return 1;
    if (test_defect_L2F1())   return 1;
    if (test_defect_L1F1())   return 1;
    if (test_zero_amount_leaf()) return 1;   /* O15J review R1-F4 */
    if (test_fail_closed())   return 1;
    printf("\nALL O15J FAZ 1 PURE-V2 GENESIS TESTS PASSED (%d checks)\n",
           g_checks);
    return 0;
}
