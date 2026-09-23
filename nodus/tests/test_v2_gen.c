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

/* R3 W3 (D-17 rev 10 (8)) — the SAME §0 composition (any salt/n_alloc/
 * reverse combination cfg_make accepts), completed to a version-3
 * document. Defined here, next to cfg_make, rather than reusing the
 * later cfg_make_v3 (§4's KAT fixture, fixed at salt=0x00/n_alloc=1/
 * reverse=0): that one is defined much later in this file (it needs
 * KAT_GENESIS_TIME_MS) and this general form is needed by earlier
 * sections (§1, §2) that vary all three parameters — a forward
 * declaration would work too, but a second small helper next to the
 * composition it varies is clearer than forward-declaring into a KAT
 * fixture. */
static int cfg_make_v3_ex(cfgbox_t *b, uint8_t salt, uint32_t n_alloc,
                          int reverse) {
    if (cfg_make(b, salt, n_alloc, reverse) != 0) return -1;
    b->cfg->config_version = NODUS_V2_GEN_CONFIG_VERSION_V3;
    if (nodus_witness_v2_gen_v3_defaults(b->cfg) != 0) {
        cfg_free(b);
        return -1;
    }
    b->cfg->genesis_time_ms = 1700000000000ULL;
    b->cfg->initial_height  = 1;
    if (nodus_witness_v2_gen_v3_fill_comet_rows(b->cfg) != 0) {
        cfg_free(b);
        return -1;
    }
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

/* R3 W3 (D-17 rev 10 (8)/(9)): the merged tree's post-open chain-role
 * gate now refuses a version-2 chain on REOPEN — the closed lane's own
 * approved closure — so §1 derives a VERSION-3 chain instead. The
 * property this section proves (a complete genesis: reserve, bonds,
 * manifest, supply) is a property of the DERIVATION, not of which lane
 * produced it, so it is lane-independent; the ONE assertion that was
 * genuinely version-2-shaped (a committed height-0 `v2_blocks` row) is
 * replaced by its version-3 equivalent (D-19 rev 6 withdrew the block;
 * the identity is the stored genesis DOCUMENT instead). */
static int test_happy_path(void) {
    printf("§1 the §0 composition derives a complete version-3 genesis\n");

    cfgbox_t box;
    CHECK(cfg_make_v3_ex(&box, 0x00, 1, 0) == 0, "config (version 3)");
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
    CHECK(nodus_witness_v2_gen_derive_v3(dir, box.cfg, chain32) == 0,
          "derive succeeds");
    OK();

    char path[600];
    nodus_witness_t *w = open_chain(dir, path);
    CHECK(w != NULL, "the derived chain db opens");
    OK();

    CHECK(q1(w->db, "SELECT COUNT(*) FROM v2_blocks WHERE global_height = 0")
              == 0,
          "NO genesis block row — D-19 rev 6 withdrew it for version 3");
    {
        uint8_t got_chain[32];
        CHECK(nodus_witness_v2_gen_stored_chain_id(w, got_chain) == 0 &&
              memcmp(got_chain, chain32, 32) == 0,
              "the stored genesis document's chain_id matches the "
              "derived one — the document IS the genesis identity now");
    }
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
        CHECK(nodus_witness_v2_gen_v3_source_commit(box.cfg, expect) == 0,
              "source_commit recomputes (the version-3 binding)");
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
          "the pure-genesis probe recognises the derived chain (the "
          "manifest's own source_tag check, unaffected by the schema "
          "flip — nodus_witness_v2_gen.c's manifest construction is the "
          "same step for both lanes)");

    close_chain(w);

    /* idempotency: a second derive over the same data_path is a no-op */
    {
        uint8_t again[32];
        memset(again, 0xEE, sizeof(again));
        CHECK(nodus_witness_v2_gen_derive_v3(dir, box.cfg, again) == 0,
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

/* R3 W3 (D-17 rev 10 (8)/(9)): derives a VERSION-3 chain — the merged
 * tree's post-open chain-role gate now refuses a version-2 chain on
 * reopen, and determinism is a lane-independent property. Reports chain
 * id, the stored document's app_hash and the whole-database logical
 * digest. app_hash (D-19 rev 6 (1): the ledger's global root) is the
 * version-3 replacement for the version-2 probe's "genesis BlockID" —
 * there is no block row to read one from any more, but app_hash is the
 * same shape of fact: a 64-byte fingerprint of what genesis actually
 * produced, which two independent derivations from equal configs must
 * still agree on. */
static int derive_probe(cfgbox_t *box, const char *tag, char dir[128],
                        uint8_t chain32[32], uint8_t app_hash[64],
                        uint8_t digest[64]) {
    if (mkdir_tmp(dir, tag) != 0) return -1;
    if (nodus_witness_v2_gen_derive_v3(dir, box->cfg, chain32) != 0)
        return -1;
    char path[600];
    nodus_witness_t *w = open_chain(dir, path);
    if (!w) return -1;
    int rc = -1;
    do {
        nodus_v2_gen_config_t *cfg = calloc(1, sizeof(*cfg));
        nodus_v2_gen_alloc_t  *allocs = NULL;
        if (!cfg) break;
        int src = nodus_witness_v2_gen_stored_doc(w, cfg, &allocs);
        if (src == 0) memcpy(app_hash, cfg->app_hash, 64);
        free(allocs);
        free(cfg);
        if (src != 0) break;
        if (db_digest(w->db, digest) != 0) break;
        rc = 0;
    } while (0);
    close_chain(w);
    return rc;
}

static int test_determinism(void) {
    printf("§2 determinism twins, caller-order independence, sensitivity "
           "(version 3)\n");

    cfgbox_t a, b, r, s;
    CHECK(cfg_make_v3_ex(&a, 0x00, 3, 0) == 0, "config a");
    CHECK(cfg_make_v3_ex(&b, 0x00, 3, 0) == 0, "config b (independent, equal)");
    CHECK(cfg_make_v3_ex(&r, 0x00, 3, 1) == 0, "config r (same set, REVERSED)");
    CHECK(cfg_make_v3_ex(&s, 0x01, 3, 0) == 0, "config s (one salted pubkey set)");
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
          "TWIN: … the SAME app_hash (the version-3 replacement for the "
          "version-2 probe's genesis BlockID — D-19 rev 6)");
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
    CHECK(memcmp(ga, gs, 64) != 0, "SENSITIVITY: … and app_hash");

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
    printf("§3.5 L2-F1 — an absent supply row is a FAILURE, not a skip "
           "(version-3 rule: a height-0 row OR a stored genesis document "
           "means a genesis EXISTS)\n");

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

        /* R3-W4-S: climb the SAME handle straight to S15 (tokenomics-v3
         * P1 moved the live rung from S14 — the Comet stores AND the
         * out-of-root attendance tables). No genesis document is ever
         * stored here — only the migration ran, never
         * nodus_witness_v2_gen_derive_v3 — so this is the
         * version-3-schema analogue of the S12 case just above: a fresh
         * S15 catalogue with no stored genesisDoc row must stay honest
         * pre-genesis, not be mistaken for a committed genesis merely
         * because the Comet stores now exist. */
        CHECK(nodus_witness_db_migrate_v2s15(w) == 0, "migrate to S15");
        CHECK(q1(w->db, "SELECT COUNT(*) FROM v2_blocks") == 0,
              "still no block committed");
        CHECK(nodus_witness_v2_supply_check(w) == 0,
              "SCOPE: S15 tables (cmt_state included) present, no stored "
              "genesisDoc, no supply row: still honest pre-genesis");
        close_chain(w);
        rmrf(dir);
    }

    /* ── the defect half: a chain WITH a genesis must fail ─────────────
     * R3 W3 (D-17 rev 10 (8)/(9)): version 3 — the merged tree's
     * post-open chain-role gate now refuses a version-2 chain on
     * reopen, and nodus_witness_v2_supply_check's fail-closed property
     * is lane-independent.
     *
     * R3-W4-S (D-17 rev 11 (11), the obligation this closes): a
     * version-3 chain never writes the height-0 v2_blocks row this
     * probe used to depend on exclusively — its genesis lives ONLY as
     * the stored "genesisDoc" document in cmt_state. Before this fix
     * the assertion below was RED: nodus_rt_core_invariant's genesis
     * probe saw no height-0 row, never looked at cmt_state, and
     * returned 0 (SKIPPED) instead of -1 — fail-OPEN on the exact chain
     * shape this whole test derives. */
    {
        cfgbox_t c;
        CHECK(cfg_make_v3_ex(&c, 0, 1, 0) == 0, "cfg (version 3)");
        char dir[128];
        CHECK(mkdir_tmp(dir, "f1_pure") == 0, "tmpdir");
        OK();
        CHECK(nodus_witness_v2_gen_derive_v3(dir, c.cfg, NULL) == 0, "derive");
        OK();
        nodus_witness_t *w = open_chain(dir, NULL);
        CHECK(w != NULL, "open");
        OK();
        CHECK(nodus_witness_v2_supply_check(w) == 0,
              "the gate PASSES on the intact chain (positive control)");

        /* Delete the row the whole invariant is evaluated against.
         * KILL: with the old unconditional `return 0` this check
         * returns 0 and the assertion below FAILS — the invariant was
         * skipped, not failed, for the life of the chain. On a
         * version-3 chain this stayed true even after L2-F1's original
         * fix, because that fix only ever looked for the height-0
         * v2_blocks row, which THIS chain shape never writes. */
        CHECK(run_sql(w->db, "DELETE FROM supply_tracking") == 0, "delete");
        CHECK(q1(w->db, "SELECT COUNT(*) FROM supply_tracking") == 0,
              "the row is gone");
        CHECK(nodus_witness_v2_supply_check(w) != 0,
              "an absent supply row on a version-3 chain that HAS a "
              "stored genesis document FAILS CLOSED (it is no longer "
              "silently skipped just because no height-0 row exists)");
        close_chain(w);
        rmrf(dir);
        cfg_free(&c);
    }

    OK();
    printf("  ok: absent row fails post-genesis (both a height-0 row and a "
           "stored genesis document count as \"genesis exists\"), "
           "unchanged pre-genesis (including a bare S14 climb)\n");
    return 0;
}

/* R3 W3 (D-17 rev 10 (8)/(9)): this section is SPECIFICALLY about the
 * closed version-2 lane (its bundle join), not a lane-independent
 * property, so it keeps deriving version 2 — but the merged tree's
 * post-open chain-role gate now refuses to REOPEN a version-2 chain at
 * all ("chain role: PRE-COMET LEDGER V2 (schema below S14) … the old
 * consensus lane is CLOSED in W3 (D-17 rev 10); refusing the
 * database"), so the assertion this section makes changes from "the
 * chain opens" to "the chain derives, but the production path refuses
 * to reopen it, and refuses closed for the reason this closure names".
 * The property this test ORIGINALLY proved — validator_stats and
 * chain_config_history travel to a JOINER through the genesis bundle —
 * cannot be exercised on this lane any more regardless (Delta 3 of this
 * package already established that no version-2 chain gets a bundle at
 * all any more); its coverage moved to test_v2_bundle.c's
 * test_v3_bundle, which digests validator_stats (among V3_TBL) between
 * a version-3 source and its joiner on every run. */
static int test_defect_L1F1(void) {
    printf("§3.6 L1-F1 — the closed version-2 lane derives, but the "
           "production path refuses to reopen it\n");

    cfgbox_t c;
    CHECK(cfg_make(&c, 0, 1, 0) == 0, "cfg");
    char sdir[128], jdir[128];
    CHECK(mkdir_tmp(sdir, "l1f1_src") == 0, "src dir");
    CHECK(mkdir_tmp(jdir, "l1f1_join") == 0, "joiner dir");
    OK();
    CHECK(nodus_witness_v2_gen_derive(sdir, c.cfg, NULL) == 0,
          "the closed lane still DERIVES — D-17 rev 10 (9) closes it, "
          "the deletion wave removes it");
    OK();

    nodus_witness_t *src = open_chain(sdir, NULL);
    CHECK(src == NULL,
          "the production open path REFUSES to reopen a version-2 chain "
          "— the merged tree's post-open chain-role gate (D-17 rev 10 "
          "(9)): a populated database below S14 is the closed old "
          "consensus lane");
    OK();

    rmrf(sdir);
    rmrf(jdir);
    cfg_free(&c);
    OK();
    printf("  ok: the closed lane derives but cannot be reopened "
           "(coverage for the bundle property moved to "
           "test_v2_bundle.c's test_v3_bundle)\n");
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

    /* an unknown config version.
     *
     * ⚠ THE PREMISE OF THIS CASE MOVED IN W2 (R3-C1b) AND THE VALUE HAD
     * TO CHANGE WITH IT. It used to say NODUS_V2_GEN_CONFIG_VERSION + 1,
     * i.e. 3 — and 3 is now the cometbft genesis document's version, a
     * schema this build DOES understand (nodus_witness_v2_gen.c:490-495
     * accepts 2 or 3, because every rule gen_plan_build states is shared
     * by both documents). The assertion still passed nothing: it read
     * "an unknown version rejects" while feeding a known one. + 2 is a
     * genuinely unknown schema and keeps the case meaning what its name
     * says. The version-3 half is pinned directly below rather than
     * left to this case. */
    {
        cfgbox_t c;
        CHECK(cfg_make(&c, 0, 1, 0) == 0, "cfg");
        OK();
        c.cfg->config_version = NODUS_V2_GEN_CONFIG_VERSION + 2;
        CHECK(nodus_witness_v2_gen_config_validate(c.cfg) != 0,
              "an unknown config_version REJECTS");
        cfg_free(&c);
    }

    /* ── THE POSITIVE COUNTERPART: a version-2 BODY claiming version 3.
     *
     * This is the config the case above used to build by accident, so it
     * gets asserted deliberately: every version-3 field is zero (the
     * struct is calloc'd and cfg_make never touches them), which is a
     * document with no consensus protocol and no genesis time.
     *
     * WHERE EACH REFUSAL COMES FROM, named so a future reader does not
     * have to guess which function owns the rule:
     *
     *   nodus_witness_v2_gen_config_validate   ACCEPTS it — and that is
     *       DELIBERATE, not a hole. Since W2 it answers one question:
     *       "do the rules the two documents SHARE hold?"
     *       (nodus_witness_v2_gen.c:490-495 and the @return note in
     *       nodus_witness_v2_gen.h). For this config they do: the
     *       validators, the allocations, the schedule constants and the
     *       claim window are a perfectly good version-2 body. A 0 here
     *       means "the shared rules pass", never "derivable". Asserting
     *       the 0 pins that scope: if someone later makes this function
     *       version-aware, this line fails and points them here.
     *   nodus_witness_v2_gen_v3_validate       REFUSES, and for the
     *       RIGHT reason — consensus_protocol is 0, not cometbft
     *       (nodus_witness_v2_gen.c:2386-2392). It is the version-3
     *       verdict, and nodus_witness_v2_gen_derive_v3 runs it first.
     *   nodus_witness_v2_gen_config_encode     REFUSES (gen.c:957): the
     *       version-2 layout writer must never produce bytes for a
     *       version-3 config.
     *   nodus_witness_v2_gen_source_commit     REFUSES (gen.c:970-979),
     *       which is the choke point nodus_witness_v2_gen_derive passes
     *       through — so the version-2 derivation refuses it too, with a
     *       logged reason an operator can act on.
     *
     * Together those four are the whole lane split, asserted on ONE
     * config. */
    {
        cfgbox_t c;
        CHECK(cfg_make(&c, 0, 1, 0) == 0, "cfg");
        OK();
        c.cfg->config_version = NODUS_V2_GEN_CONFIG_VERSION_V3;

        CHECK(c.cfg->consensus_protocol == 0 &&
              c.cfg->genesis_time_ms == 0 &&
              c.cfg->n_comet_validators == 0,
              "the version-3 fields of a version-2 config are all zero");
        CHECK(nodus_witness_v2_gen_config_validate(c.cfg) == 0,
              "config_validate answers the SHARED rules only, and they "
              "hold — it is not the version-3 verdict");
        CHECK(nodus_witness_v2_gen_v3_validate(c.cfg) != 0,
              "the version-3 verdict REFUSES it: consensus_protocol is 0, "
              "and a genesis that does not name its consensus has no "
              "validity rules");

        uint8_t *enc = NULL;
        size_t   enc_len = 0;
        CHECK(nodus_witness_v2_gen_config_encode(c.cfg, &enc, &enc_len) != 0 &&
              enc == NULL,
              "the version-2 encoder REFUSES to write it");
        uint8_t sc[NODUS_V2_GEN_SRCCOMMIT_LEN];
        CHECK(nodus_witness_v2_gen_source_commit(c.cfg, sc) != 0,
              "and so does the version-2 source binding — which is what "
              "makes nodus_witness_v2_gen_derive refuse it");

        char dir[128];
        CHECK(mkdir_tmp(dir, "v2body_v3ver") == 0, "tmpdir");
        OK();
        CHECK(nodus_witness_v2_gen_derive(dir, c.cfg, NULL) != 0,
              "the version-2 derivation is REFUSED");
        CHECK(nodus_witness_v2_gen_derive_v3(dir, c.cfg, NULL) != 0,
              "and so is the version-3 derivation");
        CHECK(dir_is_clean(dir) == 1, "neither left anything behind");
        rmrf(dir);
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

/* ════════════════════════════════════════════════════════════════════
 * §5-§11 — THE VERSION-3 GENESIS DOCUMENT (D-18 rev 4, W2 / R3-C1b)
 *
 * Every vector below comes from shared/dnac/tests/genesis_v3_oracle.py,
 * which re-derives the layout in Python from the byte table in
 * nodus_witness_v2_gen.h and NEVER calls this C.  Its stage-1 control leg
 * is §5 here: the same constant, over the shipped version-2 encoder.  If
 * §5 fails, the oracle's model of the container is wrong and no §6 vector
 * means anything — which is exactly why §5 runs first and says so.
 *
 * ⚠ THE KAT SECTIONS DEPEND ON THE BUILD'S ECONOMIC CONSTANTS.
 * DNAC_EPOCH_LENGTH, DNAC_BLOCKS_PER_YEAR and DNAC_DECIMAL_UNIT are
 * `#ifndef`-guarded and reach the encoding, so a binary built with -D
 * overrides (the Genesis Protocol short-epoch scenarios do exactly that)
 * encodes different bytes.  Those sections then DO NOT RUN and say so on
 * stdout and in the summary.  A skip is not a pass: the count is printed
 * separately and the relative checks (§7 sensitivity, §8 rejects, §9
 * document, §10 derivation, §11 row equality) run at ANY constants.
 * ══════════════════════════════════════════════════════════════════ */

static int g_kat_skipped = 0;

/* The constants the vectors were generated at (the shipped defaults:
 * dnac.h:72, :137, :172, :187 and nodus_witness_emission.h:34, :42). */
static int kat_constants_match(void) {
    return (uint64_t)DNAC_EPOCH_LENGTH        == 720ULL &&
           (uint64_t)DNAC_BLOCKS_PER_YEAR     == 6307200ULL &&
           (uint64_t)DNAC_DECIMAL_UNIT        == 100000000ULL &&
           (uint64_t)DNAC_SELF_STAKE_AMOUNT   == 1000000000000000ULL &&
           (uint64_t)DNAC_DEFAULT_TOTAL_SUPPLY == 100000000000000000ULL &&
           (unsigned)DNAC_COMMITTEE_SIZE      == 7u;
}

static void kat_announce_skip(const char *section) {
    g_kat_skipped++;
    printf("  ⚠ %s NOT RUN — this binary's economic constants differ from "
           "the vectors' (epoch=%llu blocks_per_year=%llu decimal=%llu). "
           "That coverage did NOT happen.\n", section,
           (unsigned long long)DNAC_EPOCH_LENGTH,
           (unsigned long long)DNAC_BLOCKS_PER_YEAR,
           (unsigned long long)DNAC_DECIMAL_UNIT);
}

/* Compare raw bytes against a lowercase-hex literal. */
static int hex_eq(const uint8_t *b, size_t n, const char *hex) {
    static const char d[] = "0123456789abcdef";
    if (strlen(hex) != n * 2) return 0;
    for (size_t i = 0; i < n; i++) {
        if (hex[2 * i]     != d[b[i] >> 4])   return 0;
        if (hex[2 * i + 1] != d[b[i] & 0x0F]) return 0;
    }
    return 1;
}

/* ── the oracle's vectors ────────────────────────────────────────────
 * genesis_v3_oracle.py, stage 1 and stage 2 output, 2026-09-16. */

#define KAT_GENESIS_TIME_MS  1767225600000ULL   /* 2026-01-01T00:00:00Z */
#define KAT_V2_ENC_LEN       37481u
#define KAT_A_ENC_LEN        56121u
#define KAT_B_ENC_LEN        56130u
#define KAT_C_ENC_LEN        56131u
#define KAT_D_ENC_LEN        56121u

static const char *KAT_V2_ENC_SHA =
    "92bd62f51df63ebf30a68c4fde32c7965d72ebd1ca4c3d20649998abe5be69af"
    "856534cccca070f4fc039ca523d31e53d877ca5d5ac18c9a3d04759fcd3ffca0";

static const char *KAT_A_ENC_SHA =
    "47d6c83089dd3f5616a782227872cea62171be6d8fb7dd30f056edbeee5dba08"
    "057ac178ef1eefbab3b35178f1aa1607854744f809baf360e514d8c3af50768f";
static const char *KAT_A_CHAIN_ID =
    "47d6c83089dd3f5616a782227872cea62171be6d8fb7dd30f056edbeee5dba08";
static const char *KAT_A_SRC_COMMIT =
    "47d6c83089dd3f5616a782227872cea62171be6d8fb7dd30f056edbeee5dba08"
    "057ac178ef1eefbab3b35178f1aa1607854744f809baf360e514d8c3af50768f";

static const char *KAT_B_ENC_SHA =
    "8d5b54e7123685eb3cde15e5ed193f53f1ec1e800b14772a65c295dfcbdaba32"
    "9171a07ec6ae643f42336cc7152273c623fd30cdd63174efc99b72159f1a7b04";
static const char *KAT_B_CHAIN_ID =
    "96c5a7ceeb43249096a6e29ad423094c50139f30561eebcc52e5c26b90debc5d";
static const char *KAT_B_SRC_COMMIT =
    "999717b830021ec9cba8e79d0376cc454d38b01a7b25d033dfe592b63c76f3fc"
    "7b74307ba178c9ffbfc50f648dd31fefd1d0ac5956a53fd44cc4c840d1d937bc";

static const char *KAT_C_ENC_SHA =
    "bb6ae4559057a42d8cc54bef6c5fbc00f8770fdf5bc6da106e6873709b09f5f9"
    "761dc7487e7059dfe1075f5b0c6db22a6e04771a5ebad9eee0aa4b30679206e8";
static const char *KAT_C_CHAIN_ID =
    "bb6ae4559057a42d8cc54bef6c5fbc00f8770fdf5bc6da106e6873709b09f5f9";

static const char *KAT_D_ENC_SHA =
    "579d4820bd3193bd49ddc154236d89701775c9206894d5d69eb7a6f912916eef"
    "590b7c8af21fc92fe051fee7c956558b4ece86cbb3d93b7b7f9fec17f8ecae51";
static const char *KAT_D_CHAIN_ID =
    "a1c16107b6744e705396d1c2c2156616c16c478f4b6691b233fe64be9772af96";

/* ── the version-3 fixtures (the oracle's make_v3, transcribed) ─────── */

/* A — the DEFAULTS document: default consensus params, default
 * tokenomics, empty names, app_hash and chain_id still zero (an
 * operator's config, before any derivation has completed it). */
static int cfg_make_v3(cfgbox_t *b) {
    if (cfg_make(b, 0x00, 1, 0) != 0) return -1;
    if (nodus_witness_v2_gen_v3_defaults(b->cfg) != 0) { cfg_free(b); return -1; }
    b->cfg->genesis_time_ms = KAT_GENESIS_TIME_MS;
    b->cfg->initial_height  = 1;
    if (nodus_witness_v2_gen_v3_fill_comet_rows(b->cfg) != 0) {
        cfg_free(b);
        return -1;
    }
    return 0;
}

/* B — EVERY appended field away from its default. */
static int cfg_make_v3_b(cfgbox_t *b) {
    if (cfg_make_v3(b) != 0) return -1;
    nodus_v2_gen_config_t *c = b->cfg;
    c->genesis_time_ms = 1234567890123ULL;
    c->initial_height  = 12345ULL;
    c->consensus_params.block.max_bytes              = 1234567;
    c->consensus_params.block.max_gas                = 99;
    c->consensus_params.evidence.max_age_num_blocks  = 7;
    c->consensus_params.evidence.max_age_duration_ns =
        (int64_t)3600 * 1000000000;
    c->consensus_params.evidence.max_bytes           = 4096;
    memset(c->consensus_params.validator.pub_key_types, 0,
           sizeof(c->consensus_params.validator.pub_key_types));
    snprintf(c->consensus_params.validator.pub_key_types[0],
             CMT_PARAMS_PUBKEY_TYPE_MAX, "%s", "mldsa87");
    snprintf(c->consensus_params.validator.pub_key_types[1],
             CMT_PARAMS_PUBKEY_TYPE_MAX, "%s", "testkey");
    c->consensus_params.validator.pub_key_types_len = 2;
    c->consensus_params.version.app = 9;
    c->consensus_params.abci.vote_extensions_enable_height = 5;
    for (int i = 0; i < 64; i++) c->app_hash[i] = (uint8_t)(0x77 + i * 7);
    for (int i = 0; i < 32; i++) c->chain_id[i] = (uint8_t)(0x99 + i * 5);
    c->reward_pool_initial    = 123456789ULL;
    c->reward_divisor_log2    = 15ULL;
    c->payout_interval_epochs = 7ULL;
    return 0;
}

/* C — two named rows and one explicitly empty. */
static int cfg_make_v3_c(cfgbox_t *b) {
    if (cfg_make_v3(b) != 0) return -1;
    nodus_v2_gen_config_t *c = b->cfg;
    snprintf(c->comet_validators[0].name, NODUS_V2_GEN_CMT_NAME_MAX,
             "%s", "alpha");
    c->comet_validators[0].name_len = 5;
    snprintf(c->comet_validators[1].name, NODUS_V2_GEN_CMT_NAME_MAX,
             "%s", "bravo");
    c->comet_validators[1].name_len = 5;
    c->comet_validators[2].name[0] = '\0';
    c->comet_validators[2].name_len = 0;
    return 0;
}

/* D — a COMPLETED document: app_hash present and chain_id holding its
 * own value, the shape the derivation stores under "genesisDoc". */
static int cfg_make_v3_d(cfgbox_t *b) {
    if (cfg_make_v3(b) != 0) return -1;
    for (int i = 0; i < 64; i++)
        b->cfg->app_hash[i] = (uint8_t)(0x20 + i * 3);
    uint8_t id[32];
    if (nodus_witness_v2_gen_chain_id(b->cfg, id) != 0) {
        cfg_free(b);
        return -1;
    }
    memcpy(b->cfg->chain_id, id, 32);
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * §5 — THE CONTROL LEG: the oracle reproduces the SHIPPED version-2
 *      encoder byte for byte.
 *
 * PROVES  the Python model of the canonical container equals the C that
 *         has been deriving chains since O15J. Without it, every §6
 *         vector is an echo of an unverified model.
 * SOURCE  genesis_v3_oracle.py stage 1 (CONTROL_V2_ENC_SHA / _LEN).
 * LIES?   only if this build's economic constants differ — in which case
 *         it DOES NOT RUN and says so.
 * AT BASE red: the fixture is unchanged but this assertion is new.
 * ══════════════════════════════════════════════════════════════════ */

static int test_v3_control(void) {
    printf("§5 the oracle reproduces the shipped version-2 encoding\n");
    if (!kat_constants_match()) {
        kat_announce_skip("§5 (and with it every §6 vector)");
        return 0;
    }
    cfgbox_t box;
    CHECK(cfg_make(&box, 0x00, 1, 0) == 0, "config");
    OK();
    uint8_t *enc = NULL;
    size_t   len = 0;
    CHECK(nodus_witness_v2_gen_config_encode(box.cfg, &enc, &len) == 0,
          "the version-2 config encodes");
    OK();
    CHECK(len == KAT_V2_ENC_LEN, "the encoding is 37481 bytes");
    uint8_t d[64];
    CHECK(qgp_sha3_512(enc, len, d) == 0, "digest");
    CHECK(hex_eq(d, 64, KAT_V2_ENC_SHA),
          "SHA3-512(version-2 encoding) == the oracle's control constant");
    /* source_commit IS that digest — stated by the header, asserted here
     * so the two can never drift into two definitions. */
    uint8_t sc[NODUS_V2_GEN_SRCCOMMIT_LEN];
    CHECK(nodus_witness_v2_gen_source_commit(box.cfg, sc) == 0, "commit");
    CHECK(memcmp(sc, d, 64) == 0,
          "source_commit is SHA3-512 of exactly those bytes");
    free(enc);
    cfg_free(&box);
    OK();
    printf("  ok: the oracle and the shipped encoder agree\n");
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * §6 — the version-3 KAT vectors.
 *
 * PROVES  the C writes the bytes D-18 rev 4 specifies: four documents,
 *         their encodings, their chain ids and their source commits.
 * SOURCE  genesis_v3_oracle.py stage 2 (A, B, C, D).
 * LIES?   if the build's constants differ it does not run (see §5). A
 *         and C carry a zero app_hash and a zero chain_id, so for them
 *         the document, the chain-id preimage and the source-commit
 *         preimage are the SAME bytes and the three numbers coincide —
 *         that is a property, not a bug, and B and D are the vectors
 *         where all three differ.
 * AT BASE red: none of these functions exists.
 * ══════════════════════════════════════════════════════════════════ */

static int v3_vector(const char *tag, cfgbox_t *box, size_t want_len,
                     const char *enc_sha, const char *chain_hex,
                     const char *src_hex) {
    uint8_t *enc = NULL;
    size_t   len = 0;
    if (nodus_witness_v2_gen_v3_encode(box->cfg, &enc, &len) != 0) {
        fprintf(stderr, "vector %s: encode failed\n", tag);
        g_fail = 1;
        return -1;
    }
    g_checks++;
    if (len != want_len) {
        fprintf(stderr, "vector %s: length %zu != %zu\n", tag, len, want_len);
        g_fail = 1;
    }
    uint8_t d[64];
    g_checks++;
    if (qgp_sha3_512(enc, len, d) != 0 || !hex_eq(d, 64, enc_sha)) {
        fprintf(stderr, "vector %s: encoding digest mismatch\n", tag);
        g_fail = 1;
    }
    free(enc);

    uint8_t id[32];
    g_checks++;
    if (nodus_witness_v2_gen_chain_id(box->cfg, id) != 0 ||
        !hex_eq(id, 32, chain_hex)) {
        fprintf(stderr, "vector %s: chain id mismatch\n", tag);
        g_fail = 1;
    }
    if (src_hex) {
        uint8_t sc[NODUS_V2_GEN_SRCCOMMIT_LEN];
        g_checks++;
        if (nodus_witness_v2_gen_v3_source_commit(box->cfg, sc) != 0 ||
            !hex_eq(sc, 64, src_hex)) {
            fprintf(stderr, "vector %s: source_commit mismatch\n", tag);
            g_fail = 1;
        }
    }
    return 0;
}

static int test_v3_vectors(void) {
    printf("§6 the version-3 KAT vectors\n");
    if (!kat_constants_match()) {
        kat_announce_skip("§6");
        return 0;
    }
    cfgbox_t a, b, c, d;
    CHECK(cfg_make_v3(&a)   == 0, "fixture A");
    CHECK(cfg_make_v3_b(&b) == 0, "fixture B");
    CHECK(cfg_make_v3_c(&c) == 0, "fixture C");
    CHECK(cfg_make_v3_d(&d) == 0, "fixture D");
    OK();

    v3_vector("A", &a, KAT_A_ENC_LEN, KAT_A_ENC_SHA, KAT_A_CHAIN_ID,
              KAT_A_SRC_COMMIT);
    v3_vector("B", &b, KAT_B_ENC_LEN, KAT_B_ENC_SHA, KAT_B_CHAIN_ID,
              KAT_B_SRC_COMMIT);
    v3_vector("C", &c, KAT_C_ENC_LEN, KAT_C_ENC_SHA, KAT_C_CHAIN_ID, NULL);
    v3_vector("D", &d, KAT_D_ENC_LEN, KAT_D_ENC_SHA, KAT_D_CHAIN_ID, NULL);

    /* D differs from A ONLY in app_hash and chain_id — both blanked in
     * the source-commit preimage — so their source commits MUST be the
     * same value, and their chain ids must not be. */
    {
        uint8_t sa[64], sd[64], ia[32], id[32];
        CHECK(nodus_witness_v2_gen_v3_source_commit(a.cfg, sa) == 0 &&
              nodus_witness_v2_gen_v3_source_commit(d.cfg, sd) == 0,
              "both source commits compute");
        CHECK(memcmp(sa, sd, 64) == 0,
              "app_hash and chain_id are outside the source_commit preimage");
        CHECK(nodus_witness_v2_gen_chain_id(a.cfg, ia) == 0 &&
              nodus_witness_v2_gen_chain_id(d.cfg, id) == 0, "both ids");
        CHECK(memcmp(ia, id, 32) != 0,
              "app_hash IS inside the chain-id preimage");
    }

    /* the version-2 encoder must refuse a version-3 config outright */
    {
        uint8_t *x = NULL;
        size_t   xl = 0;
        CHECK(nodus_witness_v2_gen_config_encode(a.cfg, &x, &xl) != 0 &&
              x == NULL,
              "the version-2 encoder REFUSES a version-3 config");
        uint8_t sc[64];
        CHECK(nodus_witness_v2_gen_source_commit(a.cfg, sc) != 0,
              "and so does the version-2 source_commit");
    }

    cfg_free(&a); cfg_free(&b); cfg_free(&c); cfg_free(&d);
    OK();
    printf("  ok: four documents, their ids and their commits\n");
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * §7 — every field reaches the chain id, and the two zeroing rules.
 *
 * PROVES  no appended field is decorative: flipping ANY one of them
 *         alone changes the chain id, so two configs that differ
 *         anywhere derive different chains. And the two rules the header
 *         states: the chain_id field itself does not change the chain
 *         id, app_hash does not change the source commit.
 * SOURCE  D-18 rev 4 HASHES; the oracle's sensitivity table.
 * LIES?   it would still pass if the encoder hashed the whole config
 *         struct instead of the canonical bytes — §6 is what pins the
 *         BYTES. The two together are the claim.
 * AT BASE red: the functions do not exist.
 * ══════════════════════════════════════════════════════════════════ */

#define V3_SENS(label, mutation) do {                                     \
    cfgbox_t m;                                                           \
    if (cfg_make_v3(&m) != 0) { g_fail = 1; break; }                      \
    { nodus_v2_gen_config_t *c = m.cfg; (void)c; mutation; }              \
    uint8_t got[32];                                                      \
    g_checks++;                                                           \
    if (nodus_witness_v2_gen_chain_id(m.cfg, got) != 0 ||                 \
        memcmp(got, base, 32) == 0) {                                     \
        fprintf(stderr, "sensitivity: %s does NOT reach the chain id\n",  \
                (label));                                                 \
        g_fail = 1;                                                       \
    }                                                                     \
    cfg_free(&m);                                                         \
} while (0)

static int test_v3_sensitivity(void) {
    printf("§7 every appended field reaches the chain id\n");

    cfgbox_t a;
    CHECK(cfg_make_v3(&a) == 0, "fixture A");
    OK();
    uint8_t base[32];
    CHECK(nodus_witness_v2_gen_chain_id(a.cfg, base) == 0, "base id");
    OK();

    /* one version-2 field: inflation_start_block is the free one, so a
     * flip stays inside the shared rules and isolates the encoding. */
    V3_SENS("inflation_start_block", c->inflation_start_block = 2);

    V3_SENS("consensus_protocol", c->consensus_protocol = 2);
    V3_SENS("genesis_time_ms",    c->genesis_time_ms = KAT_GENESIS_TIME_MS + 1);
    V3_SENS("initial_height",     c->initial_height = 2);
    V3_SENS("block.max_bytes",    c->consensus_params.block.max_bytes = 22020097);
    V3_SENS("block.max_gas",      c->consensus_params.block.max_gas = -2);
    V3_SENS("evidence.max_age_num_blocks",
            c->consensus_params.evidence.max_age_num_blocks = 100001);
    V3_SENS("evidence.max_age_duration",
            c->consensus_params.evidence.max_age_duration_ns += 1);
    V3_SENS("evidence.max_bytes",
            c->consensus_params.evidence.max_bytes = 1048577);
    V3_SENS("pub_key_types", c->consensus_params.validator.pub_key_types[0][6] = '8');
    V3_SENS("version.app",   c->consensus_params.version.app = 1);
    V3_SENS("abci.vote_extensions_enable_height",
            c->consensus_params.abci.vote_extensions_enable_height = 1);
    V3_SENS("comet row power",   c->comet_validators[0].power = 1);
    V3_SENS("comet row address", c->comet_validators[0].address[0] ^= 0xFF);
    V3_SENS("comet row name",
            { c->comet_validators[0].name[0] = 'x';
              c->comet_validators[0].name[1] = '\0';
              c->comet_validators[0].name_len = 1; });
    V3_SENS("app_hash",          c->app_hash[0] ^= 0xFF);
    V3_SENS("reward_pool_initial",    c->reward_pool_initial = 1);
    V3_SENS("reward_divisor_log2",    c->reward_divisor_log2 = 17);
    V3_SENS("payout_interval_epochs", c->payout_interval_epochs = 25);

    /* THE TWO ZEROING RULES. */
    {
        cfgbox_t z;
        CHECK(cfg_make_v3(&z) == 0, "fixture");
        OK();
        memset(z.cfg->chain_id, 0x42, 32);
        uint8_t got[32];
        CHECK(nodus_witness_v2_gen_chain_id(z.cfg, got) == 0 &&
              memcmp(got, base, 32) == 0,
              "the chain_id FIELD is blanked in its own preimage");
        cfg_free(&z);
    }
    {
        cfgbox_t p, q;
        CHECK(cfg_make_v3(&p) == 0 && cfg_make_v3(&q) == 0, "fixtures");
        OK();
        memset(q.cfg->app_hash, 0x11, 64);
        uint8_t sp[64], sq[64];
        CHECK(nodus_witness_v2_gen_v3_source_commit(p.cfg, sp) == 0 &&
              nodus_witness_v2_gen_v3_source_commit(q.cfg, sq) == 0,
              "both commits");
        CHECK(memcmp(sp, sq, 64) == 0,
              "app_hash is blanked in the source_commit preimage");
        /* and the source commit is NOT insensitive to everything else */
        memset(q.cfg->app_hash, 0, 64);
        q.cfg->reward_divisor_log2 = 17;
        CHECK(nodus_witness_v2_gen_v3_source_commit(q.cfg, sq) == 0 &&
              memcmp(sp, sq, 64) != 0,
              "but every other field still reaches it");
        cfg_free(&p);
        cfg_free(&q);
    }

    cfg_free(&a);
    OK();
    printf("  ok: 19 fields reach the id; the two blankings hold\n");
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * §8 — the decoder is strict.
 *
 * PROVES  a document round-trips exactly, and every malformed byte
 *         sequence the layout forbids is REFUSED rather than read as a
 *         prefix, a default or a truncation.
 * SOURCE  the header's decoder contract (D-18 rev 4 + the port's own
 *         bounds: CMT_PARAMS_MAX_PUBKEY_TYPES, name_len <= 63).
 * LIES?   a decoder that refused EVERYTHING would pass every reject case
 *         — the round-trip leg is what stops that, so it runs first and
 *         its failure is fatal to the section.
 * AT BASE red: the decoder does not exist.
 * ══════════════════════════════════════════════════════════════════ */

static int v3_reject(const char *what, const uint8_t *buf, size_t len) {
    nodus_v2_gen_config_t *cfg = calloc(1, sizeof(*cfg));
    nodus_v2_gen_alloc_t  *al  = NULL;
    g_checks++;
    if (!cfg) { g_fail = 1; return -1; }
    int rc = nodus_witness_v2_gen_v3_decode(buf, len, cfg, &al);
    if (rc == 0) {
        fprintf(stderr, "decoder ACCEPTED what it must refuse: %s\n", what);
        g_fail = 1;
    }
    free(al);
    free(cfg);
    return 0;
}

static int test_v3_decode(void) {
    printf("§8 the version-3 decoder is strict\n");

    cfgbox_t d;
    CHECK(cfg_make_v3_d(&d) == 0, "fixture D (a completed document)");
    OK();
    uint8_t *enc = NULL;
    size_t   len = 0;
    CHECK(nodus_witness_v2_gen_v3_encode(d.cfg, &enc, &len) == 0, "encode");
    OK();

    /* ── round trip: decode, then RE-ENCODE and compare bytes. Field-by
     * field equality would miss a field the decoder dropped; the bytes
     * cannot. */
    {
        nodus_v2_gen_config_t *back = calloc(1, sizeof(*back));
        nodus_v2_gen_alloc_t  *al = NULL;
        CHECK(back != NULL, "alloc");
        OK();
        CHECK(nodus_witness_v2_gen_v3_decode(enc, len, back, &al) == 0,
              "the document decodes");
        OK();
        uint8_t *again = NULL;
        size_t   alen = 0;
        CHECK(nodus_witness_v2_gen_v3_encode(back, &again, &alen) == 0,
              "the decoded config re-encodes");
        CHECK(alen == len && again && memcmp(again, enc, len) == 0,
              "byte-for-byte the same document");
        /* and the scalars a reader will actually act on */
        CHECK(back->config_version == NODUS_V2_GEN_CONFIG_VERSION_V3 &&
              back->consensus_protocol == NODUS_V2_GEN_CONSENSUS_COMETBFT &&
              back->genesis_time_ms == KAT_GENESIS_TIME_MS &&
              back->initial_height == 1 &&
              back->n_validators == N_VAL &&
              back->n_comet_validators == N_VAL &&
              back->n_allocs == 1,
              "the decoded scalars are the config's");
        CHECK(memcmp(back->chain_id, d.cfg->chain_id, 32) == 0 &&
              memcmp(back->app_hash, d.cfg->app_hash, 64) == 0,
              "app_hash and chain_id survive the round trip");
        CHECK(memcmp(&back->consensus_params, &d.cfg->consensus_params,
                     sizeof(back->consensus_params)) == 0,
              "and so do the consensus parameters, byte for byte");
        free(again);
        free(al);
        free(back);
        OK();
    }

    /* ── truncation at three boundaries ─────────────────────────────── */
    v3_reject("one byte short", enc, len - 1);
    v3_reject("the whole tail missing", enc, KAT_V2_ENC_LEN);
    v3_reject("mid-tail", enc, KAT_V2_ENC_LEN + 10);

    /* ── a trailing byte ────────────────────────────────────────────── */
    {
        uint8_t *longer = malloc(len + 1);
        CHECK(longer != NULL, "alloc");
        OK();
        memcpy(longer, enc, len);
        longer[len] = 0x00;
        v3_reject("a trailing byte", longer, len + 1);
        free(longer);
    }

    /* ── a version-2 encoding fed to the version-3 decoder ──────────── */
    {
        cfgbox_t v2;
        CHECK(cfg_make(&v2, 0x00, 1, 0) == 0, "v2 config");
        OK();
        uint8_t *v2enc = NULL;
        size_t   v2len = 0;
        CHECK(nodus_witness_v2_gen_config_encode(v2.cfg, &v2enc, &v2len) == 0,
              "v2 encodes");
        OK();
        v3_reject("a version-2 encoding", v2enc, v2len);
        free(v2enc);
        cfg_free(&v2);
    }

    /* ── values the encoder can write and a DOCUMENT may not carry ─── */
    {
        cfgbox_t m;
        uint8_t *e = NULL;
        size_t   l = 0;

        CHECK(cfg_make_v3(&m) == 0, "fixture"); OK();
        m.cfg->consensus_protocol = 0;
        CHECK(nodus_witness_v2_gen_v3_encode(m.cfg, &e, &l) == 0,
              "consensus_protocol 0 is WRITABLE (shape, not validity)");
        if (e) { v3_reject("consensus_protocol 0", e, l); free(e); e = NULL; }
        cfg_free(&m);

        CHECK(cfg_make_v3(&m) == 0, "fixture"); OK();
        m.cfg->genesis_time_ms = 0;
        CHECK(nodus_witness_v2_gen_v3_encode(m.cfg, &e, &l) == 0, "writable");
        if (e) { v3_reject("a zero genesis time", e, l); free(e); e = NULL; }
        cfg_free(&m);

        CHECK(cfg_make_v3(&m) == 0, "fixture"); OK();
        m.cfg->initial_height = UINT64_MAX;
        CHECK(nodus_witness_v2_gen_v3_encode(m.cfg, &e, &l) == 0, "writable");
        if (e) { v3_reject("initial_height past INT64_MAX", e, l);
                 free(e); e = NULL; }
        cfg_free(&m);

        CHECK(cfg_make_v3(&m) == 0, "fixture"); OK();
        m.cfg->consensus_params.validator.pub_key_types_len = 0;
        CHECK(nodus_witness_v2_gen_v3_encode(m.cfg, &e, &l) == 0, "writable");
        if (e) { v3_reject("an empty key-type list", e, l);
                 free(e); e = NULL; }
        cfg_free(&m);

        CHECK(cfg_make_v3(&m) == 0, "fixture"); OK();
        m.cfg->consensus_params.validator.pub_key_types[0][2] = 0x01;
        CHECK(nodus_witness_v2_gen_v3_encode(m.cfg, &e, &l) == 0, "writable");
        if (e) { v3_reject("a control byte in a key type", e, l);
                 free(e); e = NULL; }
        cfg_free(&m);

        CHECK(cfg_make_v3(&m) == 0, "fixture"); OK();
        m.cfg->n_comet_validators = (uint16_t)(N_VAL - 1);
        CHECK(nodus_witness_v2_gen_v3_encode(m.cfg, &e, &l) == 0, "writable");
        if (e) { v3_reject("fewer comet rows than validators", e, l);
                 free(e); e = NULL; }
        cfg_free(&m);
    }

    /* ── a name_len the ENCODER refuses outright (storage bound) ───── */
    {
        cfgbox_t m;
        CHECK(cfg_make_v3(&m) == 0, "fixture");
        OK();
        m.cfg->comet_validators[0].name_len =
            (uint8_t)(NODUS_V2_GEN_CMT_NAME_LEN_MAX + 1);
        uint8_t *e = NULL;
        size_t   l = 0;
        CHECK(nodus_witness_v2_gen_v3_encode(m.cfg, &e, &l) != 0 && e == NULL,
              "a name longer than 63 is not writable at all");
        cfg_free(&m);
    }

    /* ── a patched name_len inside otherwise valid bytes ─────────────
     * The offset is computed from the LAYOUT, which makes it a second,
     * independent statement of the table: body + protocol(4) + time(8) +
     * height(8) + 5 params(40) + type count(2) + one type(2 + 7) +
     * app(8) + abci(8) + row count(2) + address(32) + key(2592) +
     * power(8) lands exactly on row 0's name_len. */
    {
        const size_t off = (size_t)KAT_V2_ENC_LEN + 4 + 8 + 8 + 40 + 2 +
                           (2 + 7) + 8 + 8 + 2 + 32 + 2592 + 8;
        uint8_t *m = malloc(len);
        CHECK(m != NULL, "alloc");
        OK();
        memcpy(m, enc, len);
        CHECK(off < len && m[off] == 0,
              "the computed offset really is row 0's name_len (0 in D)");
        m[off] = (uint8_t)200;
        v3_reject("name_len 200", m, len);
        free(m);
    }

    /* ── a patched allocation source_id_len ─────────────────────────── */
    {
        const size_t off = 78 + 7 * 5323 + 4;   /* head + 7 validators +
                                                 * the allocation count  */
        uint8_t *m = malloc(len);
        CHECK(m != NULL, "alloc");
        OK();
        memcpy(m, enc, len);
        CHECK(off + 1 < len && m[off] == 0 && m[off + 1] == 64,
              "the computed offset really is source_id_len (64)");
        m[off + 1] = 63;
        v3_reject("source_id_len 63", m, len);
        free(m);
    }

    /* ── a wrong domain tag ─────────────────────────────────────────── */
    {
        uint8_t *m = malloc(len);
        CHECK(m != NULL, "alloc");
        OK();
        memcpy(m, enc, len);
        m[0] ^= 0xFF;
        v3_reject("a foreign domain tag", m, len);
        free(m);
    }

    free(enc);
    cfg_free(&d);
    OK();
    printf("  ok: the round trip, and every malformed document refused\n");
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * §9 — the port's genesis document, and the parameter defaults.
 *
 * PROVES  a version-3 config projects onto cmt_genesis_doc_t and passes
 *         the reference's ValidateAndComplete (types/genesis.go:69-106)
 *         with every field equal to the config's; and that
 *         _v3_defaults writes cmt_default_consensus_params VERBATIM.
 * SOURCE  cmt_genesis.h:119-131, cmt_params.c:47-110.
 * LIES?   the defaults comparison would pass trivially if both sides
 *         were zero — the KAT in §6 pins the ENCODED default parameters,
 *         which are not zero (22020096 / -1 / 100000 / 48h / 1MB).
 * AT BASE red: to_cmt_doc does not exist.
 * ══════════════════════════════════════════════════════════════════ */

static int test_v3_cmt_doc(void) {
    printf("§9 the document the port validates, and the defaults\n");

    /* the defaults are the PORT's own, byte for byte */
    {
        cfgbox_t a;
        CHECK(cfg_make_v3(&a) == 0, "fixture");
        OK();
        cmt_consensus_params_t want;
        cmt_default_consensus_params(&want);
        CHECK(memcmp(&a.cfg->consensus_params, &want, sizeof(want)) == 0,
              "_v3_defaults installs cmt_default_consensus_params verbatim");
        CHECK(want.block.max_bytes == 22020096 && want.block.max_gas == -1 &&
              want.evidence.max_age_num_blocks == 100000 &&
              want.evidence.max_age_duration_ns ==
                  (int64_t)48 * 3600 * 1000000000 &&
              want.evidence.max_bytes == 1048576 &&
              want.validator.pub_key_types_len == 1 &&
              strcmp(want.validator.pub_key_types[0],
                     CMT_PUBKEY_TYPE_MLDSA87_NAME) == 0 &&
              want.version.app == 0 &&
              want.abci.vote_extensions_enable_height == 0,
              "and those defaults are the reference's own values");
        /* the tokenomics defaults of the APPROVED record */
        CHECK(a.cfg->reward_pool_initial == 200000000ULL * 100000000ULL &&
              a.cfg->reward_divisor_log2 == 16ULL &&
              a.cfg->payout_interval_epochs == 24ULL,
              "tokenomics v2: 200M reserve, pool >> 16, 24-epoch payout");
        cfg_free(&a);
    }

    /* the document itself */
    {
        cfgbox_t d;
        CHECK(cfg_make_v3_d(&d) == 0, "completed fixture");
        OK();
        cmt_genesis_doc_t doc;
        cmt_genesis_validator_t vals[NODUS_V2_GEN_MAX_VALIDATORS];
        memset(&doc, 0, sizeof(doc));
        memset(vals, 0, sizeof(vals));
        CHECK(nodus_witness_v2_gen_to_cmt_doc(d.cfg, &doc, vals,
                                              NODUS_V2_GEN_MAX_VALIDATORS)
              == 0, "the port accepts the document");
        OK();
        CHECK(doc.chain_id_len == 32 &&
              memcmp(doc.chain_id, d.cfg->chain_id, 32) == 0,
              "chain_id is the 32 raw bytes of the config's");
        CHECK(doc.initial_height == 1, "initial_height");
        CHECK(doc.genesis_time.seconds == 1767225600LL &&
              doc.genesis_time.nanos == 0,
              "the milliseconds become {seconds, nanos}");
        CHECK(doc.has_consensus_params &&
              memcmp(&doc.consensus_params, &d.cfg->consensus_params,
                     sizeof(doc.consensus_params)) == 0,
              "the consensus parameters are carried unchanged");
        CHECK(doc.app_hash_len == 64 &&
              memcmp(doc.app_hash, d.cfg->app_hash, 64) == 0, "app_hash");
        CHECK(doc.validators_len == (size_t)N_VAL, "seven validators");
        int rows_ok = 1;
        for (uint16_t i = 0; i < N_VAL; i++) {
            const nodus_v2_gen_cmt_validator_t *r =
                &d.cfg->comet_validators[i];
            if (vals[i].address_len != 32 ||
                memcmp(vals[i].address, r->address, 32) != 0 ||
                !vals[i].pub_key.present ||
                memcmp(vals[i].pub_key.key, r->pub_key, 2592) != 0 ||
                vals[i].power != r->power)
                rows_ok = 0;
        }
        CHECK(rows_ok, "every row's address, key and power are the config's");
        /* Power is the whole-NODUS stake. Computed from THIS BUILD's own
         * constants — the same two values cfg_make seeds the config with
         * — so it runs at any -D settings instead of skipping silently
         * (which is what it did, and a silent skip reports coverage that
         * did not happen). At the shipped constants the expectation is
         * 10^15 / 10^8 = 10 000 000. */
        {
            int64_t want_power = (int64_t)((uint64_t)DNAC_SELF_STAKE_AMOUNT /
                                           (uint64_t)DNAC_DECIMAL_UNIT);
            CHECK(vals[0].power == want_power,
                  "power is self_stake / decimal_unit, in whole NODUS");
            CHECK(want_power > 0,
                  "and the build's constants make that a positive power — "
                  "a zero power would be refused by the port "
                  "(types/genesis.go:90-92)");
        }
        cfg_free(&d);
    }

    /* an initial_height of 0 is COMPLETED to 1 — genesis.go:79-81 */
    {
        cfgbox_t z;
        CHECK(cfg_make_v3(&z) == 0, "fixture");
        OK();
        z.cfg->initial_height = 0;
        cmt_genesis_doc_t doc;
        cmt_genesis_validator_t vals[NODUS_V2_GEN_MAX_VALIDATORS];
        memset(&doc, 0, sizeof(doc));
        memset(vals, 0, sizeof(vals));
        CHECK(nodus_witness_v2_gen_to_cmt_doc(z.cfg, &doc, vals,
                                              NODUS_V2_GEN_MAX_VALIDATORS)
              == 0 && doc.initial_height == 1,
              "a zero initial_height is completed to 1, as the reference "
              "completes it");
        cfg_free(&z);
    }

    /* refusals */
    {
        cfgbox_t z;
        cmt_genesis_doc_t doc;
        cmt_genesis_validator_t vals[NODUS_V2_GEN_MAX_VALIDATORS];

        CHECK(cfg_make_v3(&z) == 0, "fixture");
        OK();
        z.cfg->genesis_time_ms = 0;
        CHECK(nodus_witness_v2_gen_to_cmt_doc(z.cfg, &doc, vals,
                                              NODUS_V2_GEN_MAX_VALIDATORS)
              != 0,
              "a zero genesis time is refused — never filled from a clock");
        z.cfg->genesis_time_ms = KAT_GENESIS_TIME_MS;
        CHECK(nodus_witness_v2_gen_to_cmt_doc(z.cfg, &doc, vals, 3) != 0,
              "storage too small for the rows is refused, never truncated");
        cfg_free(&z);

        /* THE SHAPE GUARD, on the two fields that would otherwise write
         * past a buffer. This is a PUBLIC function: a caller may hand it
         * a hand-built config that never went through the decoder or the
         * validator, and `name_len` is a uint8_t copied into a char[64].
         * Neither case is reachable through decode→validate today —
         * which is exactly why it is asserted here rather than assumed
         * away. */
        CHECK(cfg_make_v3(&z) == 0, "fixture");
        OK();
        z.cfg->comet_validators[0].name_len =
            (uint8_t)(NODUS_V2_GEN_CMT_NAME_LEN_MAX + 1);
        CHECK(nodus_witness_v2_gen_to_cmt_doc(z.cfg, &doc, vals,
                                              NODUS_V2_GEN_MAX_VALIDATORS)
              != 0,
              "a name_len past the storage bound is REFUSED, never copied");
        z.cfg->comet_validators[0].name_len = 0;
        z.cfg->n_comet_validators =
            (uint16_t)(NODUS_V2_GEN_MAX_VALIDATORS + 1);
        {
            /* Storage that REALLY holds one row more than the config
             * array does, heap-allocated: the point is that the refusal
             * comes from the config's own bound and not from the
             * caller's capacity, so the capacity must genuinely be
             * large enough. Passing a bigger `cap` than `vals` holds
             * would be a lie to the API even though the function
             * refuses before touching it. */
            cmt_genesis_validator_t *big =
                calloc(NODUS_V2_GEN_MAX_VALIDATORS + 1, sizeof(*big));
            CHECK(big != NULL, "alloc");
            if (big) {
                CHECK(nodus_witness_v2_gen_to_cmt_doc(
                          z.cfg, &doc, big,
                          NODUS_V2_GEN_MAX_VALIDATORS + 1) != 0,
                      "more rows than the config array holds is REFUSED "
                      "even when the caller's storage would fit them");
                free(big);
            }
        }
        cfg_free(&z);
    }

    OK();
    printf("  ok: the document, the completion, the defaults\n");
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * §10 — the version-3 derivation, end to end.
 *
 * PROVES  a version-3 config derives a chain that ENDS at schema S14
 *         with NO height-0 block row, whose completed genesis document
 *         is stored under "genesisDoc", whose file name is the first 16
 *         bytes of the chain id, and whose stored id reads back through
 *         the accessor W3 will rewire the live chain id onto.
 * SOURCE  D-18 rev 4 STORAGE; node/setup.go:551; D-17 rev 7 (S14).
 * LIES?   TWO WAYS, both stated rather than hidden.
 *         (1) It CANNOT use open_chain(): nodus_witness_create_chain_db
 *         refuses a version-3 chain today, because its role derivation
 *         calls nodus_witness_v2_chain_id, which reads the height-0 row
 *         that no longer exists (nodus_witness.c:775-800,
 *         nodus_witness_v2_claims.c:186-203). That is a W3 item and is
 *         recorded as one; this test opens the database READ-ONLY, so a
 *         green here is NOT a statement that a node can boot the chain.
 *         (2) `user_version == 14` at the END does not mean the LEDGER
 *         GENESIS ran at S14 — it did not, and cannot in W2: the CORE
 *         `state_init` gate stops at S12
 *         (nodus_witness_v2_pools.c:1174-1182, W3's to widen), so the
 *         derivation applies the genesis at S12 and climbs afterwards.
 *         What this section proves is the END STATE and the order's
 *         losslessness, not that the Comet genesis works at S14. The
 *         first run that proves THAT is W3's, after the pool gate moves.
 * AT BASE red: derive_v3 does not exist.
 * ══════════════════════════════════════════════════════════════════ */

/* Open the single chain db in `dir` READ-ONLY, without the production
 * open path — see the LIES? note above. */
static sqlite3 *open_db_ro(const char *dir, uint8_t out16[16]) {
    char path[600];
    if (find_chain(dir, path, out16) != 0) return NULL;
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return NULL;
    }
    return db;
}

static int test_v3_derive(void) {
    printf("§10 the version-3 derivation\n");

    cfgbox_t box;
    CHECK(cfg_make_v3(&box) == 0, "fixture A");
    OK();
    CHECK(nodus_witness_v2_gen_v3_validate(box.cfg) == 0,
          "the fixture is a derivable version-3 config");
    OK();

    char dir[128];
    CHECK(mkdir_tmp(dir, "v3") == 0, "tmpdir");
    OK();

    uint8_t chain32[32];
    memset(chain32, 0, sizeof(chain32));
    CHECK(nodus_witness_v2_gen_derive_v3(dir, box.cfg, chain32) == 0,
          "the derivation succeeds");
    OK();

    uint8_t id16[16];
    sqlite3 *db = open_db_ro(dir, id16);
    CHECK(db != NULL, "the derived database opens read-only");
    OK();

    CHECK(memcmp(id16, chain32, 16) == 0,
          "the file name is the first 16 bytes of the chain id");
    CHECK(q1(db, "PRAGMA user_version") == (int64_t)NODUS_V2_SCHEMA_VERSION_S15,
          "the chain is at schema S15 — the Comet stores and the "
          "out-of-root attendance tables exist (tokenomics-v3 P1)");
    CHECK(q1(db, "SELECT COUNT(*) FROM v2_blocks") == 0,
          "there is NO genesis block row — of any height (D-19 rev 6)");
    /* ⚠ THE KEY COLUMN IS A BLOB (schema S14: `key BLOB PRIMARY KEY`)
     * and the store binds it with sqlite3_bind_blob, so a comparison
     * against a TEXT literal would compare two different storage classes
     * and match NOTHING — the query would report 0 rows for a row that is
     * there. CAST(... AS BLOB) is what makes this assertion real. */
    CHECK(q1(db, "SELECT COUNT(*) FROM cmt_state "
                 "WHERE key = CAST('genesisDoc' AS BLOB)") == 1,
          "the completed document is stored under the reference's key");
    CHECK(q1(db, "SELECT COUNT(*) FROM cmt_state "
                 "WHERE key = CAST('stateKey' AS BLOB)") == 0,
          "and stateKey is NOT written at derivation — the node's first "
          "start makes the State (node/setup.go:581)");
    CHECK(q1(db, "SELECT COUNT(*) FROM validators") == (int64_t)N_VAL,
          "seven validator rows");
    CHECK(q1(db, "SELECT COUNT(*) FROM chain_config_history") == 4,
          "the four committed economic parameters");
    CHECK(q1(db, "SELECT COALESCE(SUM(remaining),-1) FROM v2_dist_state")
              == (int64_t)TREASURY_RAW,
          "the claim reserve holds the whole treasury");

    /* the stored document IS the derived chain's identity.
     *
     * The accessor opens the store module on this READ-ONLY handle, and
     * that module prepares its INSERT and DELETE statements up front.
     * SQLite prepares them on a read-only connection without complaint
     * and refuses only at execution (measured), so a reader never
     * touches the write path — which is what lets this assertion run at
     * all, given that the production open path cannot open a version-3
     * chain yet (see the LIES? note above). */
    {
        nodus_witness_t *w = calloc(1, sizeof(*w));
        CHECK(w != NULL, "alloc");
        OK();
        w->db = db;
        uint8_t got[32];
        CHECK(nodus_witness_v2_gen_stored_chain_id(w, got) == 0 &&
              memcmp(got, chain32, 32) == 0,
              "the accessor returns the document's own chain_id");
        w->db = NULL;                 /* the db is closed below, not here */
        free(w);
    }

    /* the stored bytes decode, and the id recomputes to itself */
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(db,
                  "SELECT value FROM cmt_state "
                  "WHERE key = CAST('genesisDoc' AS BLOB)",
                  -1, &st, NULL) == SQLITE_OK, "prepare");
        CHECK(sqlite3_step(st) == SQLITE_ROW, "the row is there");
        const uint8_t *blob = sqlite3_column_blob(st, 0);
        size_t blen = (size_t)sqlite3_column_bytes(st, 0);
        nodus_v2_gen_config_t *dec = calloc(1, sizeof(*dec));
        nodus_v2_gen_alloc_t  *al = NULL;
        CHECK(dec != NULL && blob != NULL, "alloc");
        OK();
        CHECK(nodus_witness_v2_gen_v3_decode(blob, blen, dec, &al) == 0,
              "the stored document decodes STRICTLY");
        OK();
        uint8_t again[32];
        CHECK(nodus_witness_v2_gen_chain_id(dec, again) == 0 &&
              memcmp(again, chain32, 32) == 0 &&
              memcmp(dec->chain_id, chain32, 32) == 0,
              "its chain_id recomputes to itself");
        CHECK(nodus_witness_v2_gen_v3_validate(dec) == 0,
              "and its Comet rows still equal the derived rows");
        /* app_hash is the ledger's global root, not zero */
        uint8_t zero64[64];
        memset(zero64, 0, sizeof(zero64));
        CHECK(memcmp(dec->app_hash, zero64, 64) != 0,
              "app_hash carries the ledger root the apply produced");
        /* the genesis-time and tokenomics fields survived */
        CHECK(dec->genesis_time_ms == KAT_GENESIS_TIME_MS &&
              dec->reward_pool_initial == 200000000ULL * 100000000ULL,
              "the document's own fields are the config's");
        free(al);
        free(dec);
        sqlite3_finalize(st);
    }

    sqlite3_close(db);

    /* idempotency: the same config again is a no-op, not a second chain */
    {
        uint8_t again[32];
        memset(again, 0xEE, sizeof(again));
        CHECK(nodus_witness_v2_gen_derive_v3(dir, box.cfg, again) == 0,
              "a re-derivation from THIS config reports success");
        char p2[600];
        uint8_t id2[16];
        CHECK(find_chain(dir, p2, id2) == 0 && memcmp(id2, chain32, 16) == 0,
              "and left the SAME single chain db");
    }

    /* ── A TAMPERED genesisDoc ROW IS NOT AN IDENTITY ────────────────
     *
     * The accessor is the function W3 rewires the live chain id onto, so
     * what it does with a row that has been EDITED is the whole question.
     * Both cases run on a COPY of the derived database — the derivation
     * itself is never weakened to make them reachable, and the real
     * chain is untouched.
     *
     *   (a) one byte flipped inside the chain_id FIELD. It decodes, its
     *       content rules hold, and it is in canonical form — the
     *       flipped field round-trips through the encoder — so it
     *       reaches and exercises check 4 alone: the field must hash to
     *       its own document.
     *   (b) two validator entries swapped in the body. This one is the
     *       reason check 3 exists, and an earlier cut of this test
     *       asserted the wrong mechanism for it. The document DECODES
     *       (the decoder checks bounds, not order); its content rules
     *       PASS, because gen_plan_build SORTS an unsorted array instead
     *       of refusing it, so the Comet rows and the validators are
     *       both normalised before they are compared; and its id
     *       RE-HASHES to the stored field, because the re-encode sorts
     *       them back too. It fails on check 3 and nothing else: the
     *       stored bytes are not the canonical encoding of what they
     *       decode to. A field-only checksum would miss it.
     */
    {
        char src[600];
        uint8_t id16b[16];
        CHECK(find_chain(dir, src, id16b) == 0, "the derived db is there");
        OK();

        for (int tcase = 0; tcase < 2; tcase++) {
            char cdir[128];
            CHECK(mkdir_tmp(cdir, "v3tamper") == 0, "tmpdir");
            OK();
            char dst[700], cmd[1500];
            snprintf(dst, sizeof(dst), "%s/witness_copy.db", cdir);
            snprintf(cmd, sizeof(cmd), "cp '%s' '%s'", src, dst);
            CHECK(system(cmd) == 0, "the database copies");
            OK();

            sqlite3 *cdb = NULL;
            CHECK(sqlite3_open_v2(dst, &cdb, SQLITE_OPEN_READWRITE, NULL)
                  == SQLITE_OK, "the copy opens read-write");
            OK();

            /* read the stored document out */
            uint8_t *doc = NULL;
            size_t   dlen = 0;
            {
                sqlite3_stmt *st = NULL;
                CHECK(sqlite3_prepare_v2(cdb,
                          "SELECT value FROM cmt_state "
                          "WHERE key = CAST('genesisDoc' AS BLOB)",
                          -1, &st, NULL) == SQLITE_OK, "prepare");
                CHECK(sqlite3_step(st) == SQLITE_ROW, "the row is there");
                dlen = (size_t)sqlite3_column_bytes(st, 0);
                doc = malloc(dlen);
                CHECK(doc != NULL && dlen > 0, "alloc");
                if (doc) memcpy(doc, sqlite3_column_blob(st, 0), dlen);
                sqlite3_finalize(st);
            }
            OK();

            if (tcase == 0) {
                /* The chain_id field is the 32 bytes that sit 24 bytes
                 * (the three tokenomics u64s) before the end. The offset
                 * is ASSERTED against the known id before anything is
                 * flipped, so a layout drift fails here instead of
                 * silently patching some other field. */
                const size_t off = dlen - 24 - 32;
                CHECK(memcmp(doc + off, chain32, 32) == 0,
                      "the computed offset really is the chain_id field");
                doc[off] ^= 0x01;
            } else {
                /* Validator entries 0 and 1 of the body, 5323 bytes each
                 * from offset 78. Swapping them breaks the pubkey-ASC
                 * order the encoding requires. */
                const size_t v0 = 78, v1 = 78 + 5323, vlen = 5323;
                CHECK(memcmp(doc + v0, doc + v1, vlen) != 0,
                      "the two validator entries differ to begin with");
                uint8_t *tmp = malloc(vlen);
                CHECK(tmp != NULL, "alloc");
                OK();
                memcpy(tmp, doc + v0, vlen);
                memcpy(doc + v0, doc + v1, vlen);
                memcpy(doc + v1, tmp, vlen);
                free(tmp);
            }

            {
                sqlite3_stmt *st = NULL;
                CHECK(sqlite3_prepare_v2(cdb,
                          "UPDATE cmt_state SET value = ?1 "
                          "WHERE key = CAST('genesisDoc' AS BLOB)",
                          -1, &st, NULL) == SQLITE_OK, "prepare update");
                sqlite3_bind_blob(st, 1, doc, (int)dlen, SQLITE_STATIC);
                CHECK(sqlite3_step(st) == SQLITE_DONE, "the row is rewritten");
                sqlite3_finalize(st);
            }
            OK();

            nodus_witness_t *w = calloc(1, sizeof(*w));
            CHECK(w != NULL, "alloc");
            OK();
            w->db = cdb;
            uint8_t got[32];
            memset(got, 0xAB, sizeof(got));
            CHECK(nodus_witness_v2_gen_stored_chain_id(w, got) != 0,
                  tcase == 0
                      ? "a chain_id field that does not hash to its own "
                        "document is REFUSED, not returned"
                      : "a document that is not in CANONICAL FORM (its "
                        "validators are stored out of order) is REFUSED, "
                        "not returned");
            {
                uint8_t untouched[32];
                memset(untouched, 0xAB, sizeof(untouched));
                CHECK(memcmp(got, untouched, 32) == 0,
                      "and the caller's buffer was not written");
            }
            w->db = NULL;
            free(w);
            free(doc);
            sqlite3_close(cdb);
            rmrf(cdir);
        }

        /* the UNTAMPERED database still answers, so the two refusals
         * above are the tampering and not the copy */
        {
            char dst[700], cmd[1500], cdir[128];
            CHECK(mkdir_tmp(cdir, "v3copy") == 0, "tmpdir");
            OK();
            snprintf(dst, sizeof(dst), "%s/witness_copy.db", cdir);
            snprintf(cmd, sizeof(cmd), "cp '%s' '%s'", src, dst);
            CHECK(system(cmd) == 0, "the database copies");
            sqlite3 *cdb = NULL;
            CHECK(sqlite3_open_v2(dst, &cdb, SQLITE_OPEN_READONLY, NULL)
                  == SQLITE_OK, "the copy opens");
            OK();
            nodus_witness_t *w = calloc(1, sizeof(*w));
            CHECK(w != NULL, "alloc");
            OK();
            w->db = cdb;
            uint8_t got[32];
            CHECK(nodus_witness_v2_gen_stored_chain_id(w, got) == 0 &&
                  memcmp(got, chain32, 32) == 0,
                  "an untouched copy still yields the chain id");
            w->db = NULL;
            free(w);
            sqlite3_close(cdb);
            rmrf(cdir);
        }
    }

    rmrf(dir);
    cfg_free(&box);
    OK();
    printf("  ok: S14, no block row, genesisDoc, the id from the document\n");
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * §11 — a carried Comet row that disagrees with its stake entry.
 *
 * PROVES  the rows are carried but NOT authoritative: a document whose
 *         committee does not equal the one the stake entries produce is
 *         refused, and the refusal leaves nothing behind.
 * SOURCE  D-18 rev 4 RULES ("a mismatch refuses derivation").
 * LIES?   if the ENCODER refused such a config, §7's row-sensitivity
 *         cases could not exist — so the split is asserted here too: the
 *         same config ENCODES and is REFUSED by validate and derive.
 * AT BASE red: v3_validate does not exist.
 * ══════════════════════════════════════════════════════════════════ */

static int test_v3_row_equality(void) {
    printf("§11 a Comet row that disagrees with its stake entry\n");

    struct { const char *what; int which; } cases[] = {
        { "a power that is not the stake",  0 },
        { "an address that is not the key", 1 },
        { "a key that is not the validator at that position", 2 },
        { "one row too few",                3 },
    };

    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        cfgbox_t m;
        CHECK(cfg_make_v3(&m) == 0, "fixture");
        OK();
        switch (cases[k].which) {
            case 0: m.cfg->comet_validators[0].power += 1; break;
            case 1: m.cfg->comet_validators[0].address[0] ^= 0xFF; break;
            case 2: m.cfg->comet_validators[0].pub_key[0] ^= 0xFF; break;
            default: m.cfg->n_comet_validators =
                         (uint16_t)(m.cfg->n_comet_validators - 1); break;
        }
        CHECK(nodus_witness_v2_gen_v3_validate(m.cfg) != 0,
              cases[k].what);

        /* the ENCODER still writes it — shape, not validity */
        uint8_t *e = NULL;
        size_t   l = 0;
        CHECK(nodus_witness_v2_gen_v3_encode(m.cfg, &e, &l) == 0 && e,
              "and the encoder still writes those bytes (shape vs rule)");
        free(e);

        char dir[128];
        CHECK(mkdir_tmp(dir, "v3rows") == 0, "tmpdir");
        OK();
        CHECK(nodus_witness_v2_gen_derive_v3(dir, m.cfg, NULL) != 0,
              "the derivation is REFUSED");
        CHECK(dir_is_clean(dir) == 1,
              "and the data path is untouched — no chain db, no scratch");
        rmrf(dir);
        cfg_free(&m);
    }

    /* a version-2 config must NOT derive through the version-3 entry,
     * and a version-3 config must not derive through the version-2 one */
    {
        cfgbox_t v2, v3;
        char dir[128];
        CHECK(cfg_make(&v2, 0x00, 1, 0) == 0 && cfg_make_v3(&v3) == 0,
              "fixtures");
        CHECK(mkdir_tmp(dir, "v3cross") == 0, "tmpdir");
        OK();
        CHECK(nodus_witness_v2_gen_derive_v3(dir, v2.cfg, NULL) != 0,
              "the version-3 derivation refuses a version-2 config");
        CHECK(nodus_witness_v2_gen_derive(dir, v3.cfg, NULL) != 0,
              "the version-2 derivation refuses a version-3 config");
        CHECK(dir_is_clean(dir) == 1, "neither left anything behind");
        rmrf(dir);
        cfg_free(&v2);
        cfg_free(&v3);
    }

    OK();
    printf("  ok: carried, checked, and refused when it lies\n");
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
    printf("\n=== W2 / R3-C1b — the version-3 genesis document ===\n\n");
    if (test_v3_control())     return 1;
    if (test_v3_vectors())     return 1;
    if (test_v3_sensitivity()) return 1;
    if (test_v3_decode())      return 1;
    if (test_v3_cmt_doc())     return 1;
    if (test_v3_derive())      return 1;
    if (test_v3_row_equality()) return 1;
    printf("\nALL O15J FAZ 1 + W2 GENESIS TESTS PASSED (%d checks)\n",
           g_checks);
    if (g_kat_skipped > 0)
        printf("⚠ %d KAT section(s) DID NOT RUN at this build's economic "
               "constants — that coverage is ABSENT, not green.\n",
               g_kat_skipped);
    return 0;
}
