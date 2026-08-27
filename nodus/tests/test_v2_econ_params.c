/**
 * @file nodus/tests/test_v2_econ_params.c
 * @brief Ledger V2 O15J Faz 2 Block 2C — the economic parameters are
 *        COMMITTED GENESIS STATE.
 *
 * THE DEFECT UNDER TEST. DNAC_BLOCKS_PER_YEAR, DNAC_DECIMAL_UNIT
 * (nodus_witness_emission.h:33, :41) and DNAC_EPOCH_LENGTH (dnac.h:171)
 * are `#ifndef`-guarded, so `-D` at compile time changes how much a node
 * mints and where its epoch boundaries fall — and the Stage F halving
 * test requires exactly such a build, SKIPping when one is not declared
 * (test_halving_boundaries.sh:37, :57-65). They reach the state root and,
 * up to Block 2C, appeared in NO committed field: a differently-built node
 * derived the SAME chain id, joined cleanly, and then credited a
 * different amount at some later height. Nothing on the wire showed it.
 *
 * Mirror-image half: the builder ASSERTED chain_config_history empty, so
 * the emission gate's nodus_chain_config_get_u64(..., 1ULL) fell to its
 * default forever and every derived chain minted from height 1 with no
 * way to configure that at genesis.
 *
 * ── THE TWO BINDINGS, AND WHY BOTH ARE TESTED SEPARATELY ────────────
 * The parameters travel two INDEPENDENT paths to the chain id:
 *   A. into `source_commit` (canonical config encoding → manifest →
 *      dna_bh2_genesis_block_id, nodus_witness_v2_apply.c:865);
 *   B. into committed chain_config_history ROWS (→ chain_config_root →
 *      SYSTEM root, nodus_witness_roots_v2.c:266, :285 → the same
 *      genesis BlockID), which is also the ONLY path a JOINER sees — a
 *      joiner never runs the builder, so path A cannot protect it.
 *
 * ⚠ ANTI-VACUITY / COMPOUND MUTANT. Because two independent paths defend
 * "a changed parameter is a changed chain", a SINGLE mutant of either one
 * SURVIVES an end-to-end chain-id assertion: delete the field from the
 * encoding and the committed row still moves chain_config_root; delete
 * the seeded row and source_commit still moves. §1 therefore asserts each
 * path SEPARATELY — the encoding byte-for-byte, and the committed root
 * on its own — so no single-guard mutant survives. This is stated because
 * an unqualified "change it → different chain id" test would be weaker
 * than it looks.
 *
 * Sections:
 *   §1  the parameters reach the chain id — BOTH paths, independently
 *   §2  a mismatched build is REFUSED, not silently admitted
 *   §3  the inflation start is honoured FROM GENESIS
 *   §4  the Faz 1 determinism twin still holds
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
#include "witness/nodus_witness_emission.h"
#include "witness/nodus_witness_v2_econ.h"
#include "witness/nodus_witness_v2_gen.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/dnac.h"
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

/* ── the §0 composition, identical to test_v2_gen.c ──────────────────── */

#define TREASURY_RAW   93000000000000000ULL          /* 930,000,000 DNAC */
#define N_VAL          ((uint16_t)DNAC_COMMITTEE_SIZE)

/* The canonical config layout this test PINS, from the table in
 * nodus_witness_v2_gen.h. Offsets are absolute byte positions in the
 * encoding; a field silently dropped from gen_encode_planned shifts every
 * later offset AND shortens the buffer, so both are asserted. */
#define ENC_OFF_TOTAL_SUPPLY     (16 + 4)
#define ENC_OFF_EPOCH_LENGTH     (ENC_OFF_TOTAL_SUPPLY + 8)
#define ENC_OFF_BLOCKS_PER_YEAR  (ENC_OFF_EPOCH_LENGTH + 8)
#define ENC_OFF_DECIMAL_UNIT     (ENC_OFF_BLOCKS_PER_YEAR + 8)
#define ENC_OFF_INFLATION_START  (ENC_OFF_DECIMAL_UNIT + 8)
#define ENC_OFF_CLAIM_START      (ENC_OFF_INFLATION_START + 8)
#define ENC_OFF_CLAIM_END        (ENC_OFF_CLAIM_START + 8)
#define ENC_OFF_VAL_COUNT        (ENC_OFF_CLAIM_END + 8)
#define ENC_HEAD_LEN             (ENC_OFF_VAL_COUNT + 2)

/* One validator record and one allocation record, per the same table. */
#define ENC_VAL_LEN   (DNAC_PUBKEY_SIZE + DNAC_PUBKEY_SIZE + \
                       DNAC_FINGERPRINT_SIZE + 8 + 2)
#define ENC_ALLOC_LEN (2 + 64 + 8 + 64)

/* §1.3 asserts against LITERAL param ids in SQL, deliberately — a literal
 * catches a silent renumbering that a macro would follow. Pin the two
 * representations together so they cannot drift apart instead. */
_Static_assert(NODUS_CC_ECON_BLOCKS_PER_YEAR == 200u,
               "the reserved econ band moved; test_v2_econ_params SQL "
               "still names 200");
_Static_assert(NODUS_CC_ECON_DECIMAL_UNIT == 201u,
               "the reserved econ band moved; test_v2_econ_params SQL "
               "still names 201");
_Static_assert(NODUS_CC_ECON_EPOCH_LENGTH == 202u,
               "the reserved econ band moved; test_v2_econ_params SQL "
               "still names 202");
/* And the band must stay OUTSIDE the governance space — the property
 * §2.2's scalar_rules assertion depends on. */
_Static_assert(NODUS_CC_ECON_PARAM_MIN > DNAC_CFG_PARAM_MAX_ID,
               "the econ band overlaps the governance param space");

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

static uint64_t be64_at(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | (uint64_t)p[i];
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

/* A whole-database LOGICAL digest — every user table plus sqlite_sequence,
 * rows in rowid order, each column's storage type and bytes hashed. NOT a
 * raw file hash: the SQLite file image is not a deterministic
 * representation of logical state. Same construction as test_v2_gen.c's
 * db_digest and v2_genesis_fixture.h's v2x_db_digest. */
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
 * The §0 composition with ONE treasury allocation: 7 validators each
 * bonding DNAC_SELF_STAKE_AMOUNT plus TREASURY_RAW claimable — 10^17 raw
 * in total, exactly DNAC_DEFAULT_TOTAL_SUPPLY.
 *
 * @param inflation_start the ONLY economic parameter a config may vary
 *                        and still derive: the three schedule constants
 *                        are pinned to this build (that IS the fail-closed
 *                        rule §2 exercises).
 */
static int cfg_make(cfgbox_t *b, uint8_t salt, uint64_t inflation_start) {
    memset(b, 0, sizeof(*b));
    b->cfg = calloc(1, sizeof(*b->cfg));
    b->allocs = calloc(1, sizeof(*b->allocs));
    if (!b->cfg || !b->allocs) { cfg_free(b); return -1; }

    nodus_v2_gen_config_t *c = b->cfg;
    c->config_version        = NODUS_V2_GEN_CONFIG_VERSION;
    c->total_supply_raw      = DNAC_DEFAULT_TOTAL_SUPPLY;
    c->epoch_length          = (uint64_t)DNAC_EPOCH_LENGTH;
    c->blocks_per_year       = (uint64_t)DNAC_BLOCKS_PER_YEAR;
    c->decimal_unit          = (uint64_t)DNAC_DECIMAL_UNIT;
    c->inflation_start_block = inflation_start;
    c->claim_start_height    = 0;
    c->claim_end_height      = UINT64_MAX;
    c->n_validators          = N_VAL;

    for (uint16_t i = 0; i < N_VAL; i++) {
        nodus_v2_gen_validator_t *v = &c->validators[i];
        for (size_t bb = 0; bb < DNAC_PUBKEY_SIZE; bb++) {
            v->pubkey[bb] = (uint8_t)(0x11 * (i + 1) + (bb & 0x3F) + salt);
            v->unstake_destination_pubkey[bb] =
                (uint8_t)(v->pubkey[bb] ^ 0x5A);
        }
        hex_lower_fp(v->unstake_destination_pubkey, DNAC_PUBKEY_SIZE,
                     v->unstake_destination_fp);
        v->self_stake     = DNAC_SELF_STAKE_AMOUNT;
        v->commission_bps = (uint16_t)(100 * (i + 1));
    }

    {
        nodus_v2_gen_alloc_t *a = &b->allocs[0];
        memset(a->source_id, 0, sizeof(a->source_id));
        a->source_id[0] = 0x30;
        uint8_t owner[DNAC_PUBKEY_SIZE];
        for (size_t bb = 0; bb < sizeof(owner); bb++)
            owner[bb] = (uint8_t)(0xA0 + (bb & 0x1F));
        qgp_sha3_512(owner, sizeof(owner), a->dest_binding);
        a->amount = TREASURY_RAW;
    }

    c->n_allocs = 1;
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

/* Open the single chain DB in `dir`. Caller closes + frees.
 * v2_successor is ASSERTED, never assigned — the same discipline
 * test_v2_gen.c's open_chain adopted after review R2-F2. */
static nodus_witness_t *open_chain(const char *dir) {
    uint8_t id16[16];
    char path[600];
    if (find_chain(dir, path, id16) != 0) return NULL;
    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(w->data_path, sizeof(w->data_path), "%s", dir);
    if (nodus_witness_create_chain_db(w, id16) != 0) { free(w); return NULL; }
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
    snprintf(dir, 128, "/tmp/test_v2_econ_params_%s_XXXXXX", tag);
    return mkdtemp(dir) ? 0 : -1;
}

/* Overwrite one committed econ-band row — the ONLY way to build, in a
 * test, the state a differently-built node's chain would arrive in: the
 * builder refuses to DERIVE such a chain, so the row has to be planted
 * after the fact. This is exactly the JOINER's position. */
static int poke_band(nodus_witness_t *w, unsigned param, uint64_t value) {
    char sql[200];
    snprintf(sql, sizeof(sql),
             "UPDATE chain_config_history SET new_value = %llu "
             "WHERE param_id = %u AND effective_block = %llu",
             (unsigned long long)value, param,
             (unsigned long long)NODUS_CC_ECON_EFFECTIVE_BLOCK);
    if (run_sql(w->db, sql) != 0) return -1;
    /* The raw UPDATE bypasses the mutate path that would invalidate the
     * warm chain-config cache (nodus_witness_rt_native.c:4386). The band
     * is never cached (ids >= CC_PARAM_SLOTS are skipped), but the
     * inflation-start id IS, so clearing here keeps both readers honest. */
    w->chain_config_cache_warm = false;
    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * §1 — THE PARAMETERS REACH THE CHAIN ID, BY BOTH PATHS
 * ══════════════════════════════════════════════════════════════════ */

/* §1.1 PATH A, END TO END. Two configs identical in every byte except
 * `inflation_start_block` derive DIFFERENT chain ids.
 *
 * inflation_start_block is the only economic parameter a config may vary
 * and still derive — the other three are pinned to the build — so it is
 * the only one for which a full derive-and-compare is expressible. It is
 * a genuine end-to-end proof of path A: config → canonical encoding →
 * source_commit → manifest → dna_bh2_genesis_block_id → chain id.
 *
 * MUTANT KILLED: delete `put_be64(p, cfg->inflation_start_block)` from
 * gen_encode_planned and the two configs hash identically, so the two
 * chain ids collide and this fails. Also killed: writing a constant
 * instead of the field. NOT killed by this assertion alone: dropping the
 * SEEDED ROW (path B) — §1.3 covers that, deliberately separately. */
static int t_path_a_chain_id(void) {
    char d1[128], d2[128];
    CHECK(mkdir_tmp(d1, "a1") == 0 && mkdir_tmp(d2, "a2") == 0, "tmpdirs");
    OK();

    cfgbox_t c1, c2;
    CHECK(cfg_make(&c1, 0x00, 1ULL) == 0, "cfg 1");
    CHECK(cfg_make(&c2, 0x00, 5ULL) == 0, "cfg 2");
    OK();

    /* Both configs are derivable — the difference is a legal one, not a
     * rejection. If this fails the test below proves nothing. */
    CHECK(nodus_witness_v2_gen_config_validate(c1.cfg) == 0 &&
          nodus_witness_v2_gen_config_validate(c2.cfg) == 0,
          "both inflation starts are legal configs");
    OK();

    uint8_t sc1[NODUS_V2_GEN_SRCCOMMIT_LEN], sc2[NODUS_V2_GEN_SRCCOMMIT_LEN];
    CHECK(nodus_witness_v2_gen_source_commit(c1.cfg, sc1) == 0 &&
          nodus_witness_v2_gen_source_commit(c2.cfg, sc2) == 0,
          "source_commit computed for both");
    CHECK(memcmp(sc1, sc2, sizeof(sc1)) != 0,
          "a different inflation start is a DIFFERENT source_commit");

    uint8_t id1[32], id2[32];
    CHECK(nodus_witness_v2_gen_derive(d1, c1.cfg, id1) == 0, "derive 1");
    CHECK(nodus_witness_v2_gen_derive(d2, c2.cfg, id2) == 0, "derive 2");
    OK();
    CHECK(memcmp(id1, id2, 32) != 0,
          "and therefore a DIFFERENT CHAIN ID — a mismatched economic "
          "config cannot join, it derives its own chain");

    cfg_free(&c1); cfg_free(&c2);
    rmrf(d1); rmrf(d2);
    return g_fail;
}

/* §1.2 PATH A, BYTE FOR BYTE. The three parameters a config may NOT vary
 * cannot be proven by deriving two chains — the builder refuses the
 * second. They are proven where they actually enter the identity: in the
 * canonical encoding that source_commit digests.
 *
 * Asserted: the total encoded LENGTH, each parameter's VALUE at its
 * DOCUMENTED OFFSET, and that source_commit really is SHA3-512 of exactly
 * those bytes (so the offsets are not being checked against a buffer that
 * the digest ignores).
 *
 * MUTANT KILLED: delete any one of the three `put_be64` calls — `need`
 * shrinks by 8, the length assertion fails, and every later offset shifts.
 * Also killed: swapping two fields, or writing a compile-time constant in
 * place of the config field (the offset check reads the value back). */
static int t_path_a_encoding(void) {
    cfgbox_t c;
    CHECK(cfg_make(&c, 0x00, 7ULL) == 0, "cfg");
    OK();

    uint8_t *enc = NULL;
    size_t   len = 0;
    CHECK(nodus_witness_v2_gen_config_encode(c.cfg, &enc, &len) == 0 && enc,
          "the config encodes");
    OK();

    const size_t want_len = (size_t)ENC_HEAD_LEN +
                            (size_t)N_VAL * ENC_VAL_LEN + 4 +
                            (size_t)1 * ENC_ALLOC_LEN;
    CHECK(len == want_len,
          "the encoding is exactly the documented length — a dropped "
          "economic field shortens it by 8");

    CHECK(be64_at(enc + ENC_OFF_EPOCH_LENGTH) == (uint64_t)DNAC_EPOCH_LENGTH,
          "epoch_length sits at its documented offset");
    CHECK(be64_at(enc + ENC_OFF_BLOCKS_PER_YEAR) ==
              (uint64_t)DNAC_BLOCKS_PER_YEAR,
          "blocks_per_year sits at its documented offset");
    CHECK(be64_at(enc + ENC_OFF_DECIMAL_UNIT) == (uint64_t)DNAC_DECIMAL_UNIT,
          "decimal_unit sits at its documented offset");
    CHECK(be64_at(enc + ENC_OFF_INFLATION_START) == 7ULL,
          "inflation_start_block sits at its documented offset and carries "
          "the CONFIG's value, not a constant");
    /* The fields around them must not have moved either. */
    CHECK(be64_at(enc + ENC_OFF_TOTAL_SUPPLY) ==
              (uint64_t)DNAC_DEFAULT_TOTAL_SUPPLY &&
          be64_at(enc + ENC_OFF_CLAIM_START) == 0ULL &&
          be64_at(enc + ENC_OFF_CLAIM_END) == UINT64_MAX,
          "the surrounding fields kept their offsets");

    /* THE BINDING STEP: these bytes ARE the source_commit preimage. */
    uint8_t direct[64], reported[NODUS_V2_GEN_SRCCOMMIT_LEN];
    CHECK(qgp_sha3_512(enc, len, direct) == 0, "digest the encoding");
    CHECK(nodus_witness_v2_gen_source_commit(c.cfg, reported) == 0,
          "source_commit");
    CHECK(memcmp(direct, reported, 64) == 0,
          "source_commit IS SHA3-512 of exactly those bytes — the offsets "
          "above are checked against the real preimage");

    free(enc);
    cfg_free(&c);
    return g_fail;
}

/* §1.3 PATH B, ON ITS OWN. The committed ROWS reach chain_config_root,
 * which is a SYSTEM leg (nodus_witness_roots_v2.c:266, :285) and
 * therefore a genesis-BlockID input. Changing a committed economic value
 * moves that root — so a chain built with a different blocks_per_year
 * would have had a different chain id even if path A did not exist.
 *
 * This is the SECOND half of the compound mutant. §1.1 and §1.2 both
 * survive deleting the seeded rows; this one does not. */
static int t_path_b_committed_root(void) {
    char dir[128];
    CHECK(mkdir_tmp(dir, "b") == 0, "tmpdir");
    OK();
    cfgbox_t c;
    CHECK(cfg_make(&c, 0x00, 1ULL) == 0, "cfg");
    CHECK(nodus_witness_v2_gen_derive(dir, c.cfg, NULL) == 0, "derive");
    OK();

    nodus_witness_t *w = open_chain(dir);
    CHECK(w != NULL, "open the derived chain");
    OK();

    /* The rows exist, at the pinned effective_block, with the config's
     * values — a row that is merely PRESENT proves nothing. */
    CHECK(q1(w->db, "SELECT new_value FROM chain_config_history "
                    "WHERE param_id = 200 AND effective_block = 0")
              == (int64_t)DNAC_BLOCKS_PER_YEAR,
          "blocks_per_year is a COMMITTED ROW carrying the config value");
    CHECK(q1(w->db, "SELECT new_value FROM chain_config_history "
                    "WHERE param_id = 201 AND effective_block = 0")
              == (int64_t)DNAC_DECIMAL_UNIT,
          "decimal_unit is a COMMITTED ROW carrying the config value");
    CHECK(q1(w->db, "SELECT new_value FROM chain_config_history "
                    "WHERE param_id = 202 AND effective_block = 0")
              == (int64_t)DNAC_EPOCH_LENGTH,
          "epoch_length is a COMMITTED ROW carrying the config value");
    OK();

    uint8_t before[64], after[64];
    CHECK(nodus_chain_config_compute_root(w, before) == 0, "root before");
    CHECK(poke_band(w, NODUS_CC_ECON_BLOCKS_PER_YEAR,
                    (uint64_t)DNAC_BLOCKS_PER_YEAR + 1) == 0, "poke");
    CHECK(nodus_chain_config_compute_root(w, after) == 0, "root after");
    CHECK(memcmp(before, after, 64) != 0,
          "a different committed blocks_per_year is a different "
          "chain_config_root — hence a different SYSTEM root, a different "
          "genesis BlockID and a different chain id");

    close_chain(w);
    cfg_free(&c);
    rmrf(dir);
    return g_fail;
}

/* ════════════════════════════════════════════════════════════════════
 * §2 — A MISMATCHED BUILD IS REFUSED, NOT SILENTLY ADMITTED
 * ══════════════════════════════════════════════════════════════════ */

/* §2.1 THE DERIVE SIDE. A config naming economics this build cannot
 * honour is refused before anything is written, and leaves NOTHING
 * behind.
 *
 * MUTANT KILLED: remove either equality check in gen_plan_build. NOTE
 * this is only ONE of the two guards — a node that JOINED such a chain
 * never runs this code at all, which is what §2.2 covers. */
static int t_derive_refuses_mismatch(void) {
    char dir[128];
    CHECK(mkdir_tmp(dir, "m") == 0, "tmpdir");
    OK();

    cfgbox_t c;

    /* blocks_per_year */
    CHECK(cfg_make(&c, 0x00, 1ULL) == 0, "cfg");
    c.cfg->blocks_per_year = (uint64_t)DNAC_BLOCKS_PER_YEAR + 1;
    CHECK(nodus_witness_v2_gen_config_validate(c.cfg) != 0,
          "a blocks_per_year this build cannot honour is REFUSED");
    CHECK(nodus_witness_v2_gen_derive(dir, c.cfg, NULL) != 0,
          "and derive refuses it too");
    cfg_free(&c);

    /* decimal_unit */
    CHECK(cfg_make(&c, 0x00, 1ULL) == 0, "cfg");
    c.cfg->decimal_unit = (uint64_t)DNAC_DECIMAL_UNIT * 10;
    CHECK(nodus_witness_v2_gen_config_validate(c.cfg) != 0,
          "a decimal_unit this build cannot honour is REFUSED");
    CHECK(nodus_witness_v2_gen_derive(dir, c.cfg, NULL) != 0,
          "and derive refuses it too");
    cfg_free(&c);

    /* epoch_length — the Faz 1 check, still in force */
    CHECK(cfg_make(&c, 0x00, 1ULL) == 0, "cfg");
    c.cfg->epoch_length = (uint64_t)DNAC_EPOCH_LENGTH + 1;
    CHECK(nodus_witness_v2_gen_config_validate(c.cfg) != 0,
          "an epoch_length this build cannot honour is still REFUSED");
    cfg_free(&c);

    /* the governance ceiling on the one FREE parameter */
    CHECK(cfg_make(&c, 0x00, 1ULL) == 0, "cfg");
    c.cfg->inflation_start_block = DNAC_CFG_MAX_INFLATION_START_BLOCK + 1;
    CHECK(nodus_witness_v2_gen_config_validate(c.cfg) != 0,
          "an inflation start above the governance ceiling is REFUSED — "
          "genesis must not commit a value no vote could produce");
    cfg_free(&c);

    /* a version-1 config is refused rather than defaulted: an economic
     * parameter must never arrive from a structural default */
    CHECK(cfg_make(&c, 0x00, 1ULL) == 0, "cfg");
    c.cfg->config_version = 1u;
    CHECK(nodus_witness_v2_gen_config_validate(c.cfg) != 0,
          "the pre-2C config schema is REFUSED, not defaulted");
    cfg_free(&c);

    /* FAIL-CLOSED: not one of those refusals left a chain behind. */
    {
        char p[600];
        uint8_t id16[16];
        CHECK(find_chain(dir, p, id16) == 1,
              "a refused derivation left NOTHING in the data path");
    }
    rmrf(dir);
    return g_fail;
}

/* §2.2 THE JOIN SIDE — the defect the whole change exists for.
 *
 * A joiner never runs the builder: it adopts a genesis bundle. So the
 * config→source_commit binding cannot protect it, and before Block 2C
 * nothing else did — a node built with a different DNAC_BLOCKS_PER_YEAR
 * joined cleanly and then minted a different amount. The committed rows
 * are what close it: the runtime reads them on EVERY block and refuses
 * when they disagree with the binary.
 *
 * The chain is derived normally and then its committed row is poked,
 * which reproduces exactly the state such a joiner would be in: the
 * chain's committed economics say one thing, this build says another.
 *
 * MUTANT KILLED: delete the epoch_length refusal in
 * nodus_witness_v2_econ_params_load, or the -2 conversion at the top of
 * nodus_witness_v2_emission_apply — the poked chain then mints happily on
 * the wrong parameters, which is the original defect. */
static int t_join_refuses_mismatch(void) {
    char dir[128];
    CHECK(mkdir_tmp(dir, "j") == 0, "tmpdir");
    OK();
    cfgbox_t c;
    CHECK(cfg_make(&c, 0x00, 1ULL) == 0, "cfg");
    CHECK(nodus_witness_v2_gen_derive(dir, c.cfg, NULL) == 0, "derive");
    OK();

    nodus_witness_t *w = open_chain(dir);
    CHECK(w != NULL, "open");
    OK();

    /* Baseline: an untouched chain loads cleanly and MINTS. */
    {
        nodus_v2_econ_params_t p;
        CHECK(nodus_witness_v2_econ_params_load(w, &p) == 0 && p.present,
              "the derived chain's band loads");
        CHECK(p.blocks_per_year == (uint64_t)DNAC_BLOCKS_PER_YEAR &&
              p.decimal_unit    == (uint64_t)DNAC_DECIMAL_UNIT &&
              p.epoch_length    == (uint64_t)DNAC_EPOCH_LENGTH,
              "with this build's values");
        uint64_t minted = 0;
        CHECK(nodus_witness_v2_emission_apply(w, 1, &minted) == 0 &&
              minted == nodus_emission_per_block(1),
              "and a block on it mints the scheduled amount");
    }
    OK();

    /* THE MISMATCH — epoch_length. This is the parameter the runtime
     * CHECKS rather than uses, so a refusal is the only correct outcome:
     * the macro leaks into vset/committee/graduation, and a node keying
     * its epochs differently from its peers is a split. */
    CHECK(poke_band(w, NODUS_CC_ECON_EPOCH_LENGTH,
                    (uint64_t)DNAC_EPOCH_LENGTH + 1) == 0, "poke E");
    {
        nodus_v2_econ_params_t p;
        CHECK(nodus_witness_v2_econ_params_load(w, &p) != 0,
              "a committed epoch_length this build cannot honour is a "
              "FAULT, not a value");
        uint64_t minted = 123;
        CHECK(nodus_witness_v2_emission_apply(w, 2, &minted) == -2 &&
              minted == 0,
              "and the block FAILS rather than minting on parameters this "
              "build disagrees with");
    }
    CHECK(poke_band(w, NODUS_CC_ECON_EPOCH_LENGTH,
                    (uint64_t)DNAC_EPOCH_LENGTH) == 0, "restore E");
    OK();

    /* A CORRUPT value is a fault too — 0 blocks_per_year is not a
     * schedule, and _ex would have to divide by it. */
    CHECK(poke_band(w, NODUS_CC_ECON_BLOCKS_PER_YEAR, 0ULL) == 0, "poke 0");
    {
        nodus_v2_econ_params_t p;
        CHECK(nodus_witness_v2_econ_params_load(w, &p) != 0,
              "a zero-valued committed economic parameter is REFUSED");
        uint64_t minted = 123;
        CHECK(nodus_witness_v2_emission_apply(w, 2, &minted) == -2 &&
              minted == 0, "and no block mints on it");
    }
    CHECK(poke_band(w, NODUS_CC_ECON_BLOCKS_PER_YEAR,
                    (uint64_t)DNAC_BLOCKS_PER_YEAR) == 0, "restore BY");
    OK();

    /* A PARTIAL band has no defined economics — half committed, half
     * compiled is not an answer. Absent-vs-fault is the distinction
     * nodus/CLAUDE.md demands, and this proves the loader makes it:
     * ZERO rows is `present == 0` (§2.3), SOME rows is -1. */
    CHECK(run_sql(w->db, "DELETE FROM chain_config_history "
                         "WHERE param_id = 201") == 0, "delete one row");
    w->chain_config_cache_warm = false;
    {
        nodus_v2_econ_params_t p;
        CHECK(nodus_witness_v2_econ_params_load(w, &p) != 0,
              "a PARTIAL economic band is a FAULT, never a fallback");
    }
    OK();

    /* GOVERNANCE CAN NEVER PRODUCE A BAND ROW. The band is committed
     * once, at genesis, and no committee vote may move it — the property
     * nodus_witness_emission.h states about the emission schedule.
     * MUTANT KILLED: widening the allowlist to admit these ids. */
    CHECK(nodus_chain_config_scalar_rules(
              (uint8_t)NODUS_CC_ECON_BLOCKS_PER_YEAR, 100, 1, 100, 50) != 0 &&
          nodus_chain_config_scalar_rules(
              (uint8_t)NODUS_CC_ECON_DECIMAL_UNIT, 100, 1, 100, 50) != 0 &&
          nodus_chain_config_scalar_rules(
              (uint8_t)NODUS_CC_ECON_EPOCH_LENGTH, 100, 1, 100, 50) != 0,
          "no CHAIN_CONFIG tx can ever write the reserved econ band");
    /* ...while the governable inflation start still passes its own rules,
     * so the assertion above is about the BAND and not about the checker
     * rejecting everything it is handed. */
    CHECK(nodus_chain_config_scalar_rules(
              (uint8_t)DNAC_CFG_INFLATION_START_BLOCK, 100, 1, 200, 50) == 0,
          "and the governable inflation start is still votable");

    close_chain(w);
    cfg_free(&c);
    rmrf(dir);
    return g_fail;
}

/* §2.3 THE PRE-2C CHAIN. Every chain built before this change — and every
 * seam successor, which has no operator config to express these values —
 * carries NO band. That is `present == 0`, NOT a fault, and the compiled
 * constants stand: behaviour is byte-identical to what it was.
 *
 * MUTANT KILLED: making an absent band a fault (which would brick every
 * existing chain), or making a fault look absent (which would silently
 * restore the original defect). */
static int t_preexisting_chain_unchanged(void) {
    char dir[128];
    CHECK(mkdir_tmp(dir, "p") == 0, "tmpdir");
    OK();
    cfgbox_t c;
    CHECK(cfg_make(&c, 0x00, 1ULL) == 0, "cfg");
    CHECK(nodus_witness_v2_gen_derive(dir, c.cfg, NULL) == 0, "derive");
    OK();
    nodus_witness_t *w = open_chain(dir);
    CHECK(w != NULL, "open");
    OK();

    /* Strip the whole band — the shape of a chain derived before 2C. */
    CHECK(run_sql(w->db, "DELETE FROM chain_config_history "
                         "WHERE param_id >= 200") == 0, "strip band");
    w->chain_config_cache_warm = false;

    nodus_v2_econ_params_t p;
    CHECK(nodus_witness_v2_econ_params_load(w, &p) == 0 && p.present == 0,
          "no band is ABSENT, not a fault");

    uint64_t minted = 0;
    CHECK(nodus_witness_v2_emission_apply(w, 1, &minted) == 0 &&
          minted == nodus_emission_per_block(1),
          "and such a chain mints exactly what the COMPILED constants say "
          "— byte-identical to its pre-2C behaviour");

    close_chain(w);
    cfg_free(&c);
    rmrf(dir);
    return g_fail;
}

/* ════════════════════════════════════════════════════════════════════
 * §3 — THE INFLATION START IS HONOURED FROM GENESIS
 * ══════════════════════════════════════════════════════════════════ */

/* Before Block 2C this was INEXPRESSIBLE: the builder asserted
 * chain_config_history empty, so the gate's 1ULL default stood and every
 * derived chain minted from height 1. The only way to change it was a
 * governance vote AFTER the chain was already minting.
 *
 * MUTANT KILLED: remove the DNAC_CFG_INFLATION_START_BLOCK row from
 * gen_seed_state — the gate falls back to 1ULL, the start=0 chain starts
 * minting and the start=4 chain mints at height 1. Both halves fail. */
static int t_inflation_start_from_genesis(void) {
    /* ── off for the life of the chain ─────────────────────────────── */
    {
        char dir[128];
        CHECK(mkdir_tmp(dir, "i0") == 0, "tmpdir");
        OK();
        cfgbox_t c;
        CHECK(cfg_make(&c, 0x00, 0ULL) == 0, "cfg start=0");
        CHECK(nodus_witness_v2_gen_derive(dir, c.cfg, NULL) == 0, "derive");
        OK();
        nodus_witness_t *w = open_chain(dir);
        CHECK(w != NULL, "open");
        OK();

        /* Block 2A made this read three-valued. rc MUST be 0 (found):
         * an absent row would mean the builder never committed the
         * value, which is precisely what this assertion denies. */
        uint64_t got_zero = UINT64_MAX;
        CHECK(nodus_chain_config_get_u64(
                  w, (uint8_t)DNAC_CFG_INFLATION_START_BLOCK, 0,
                  UINT64_MAX, &got_zero) == 0 && got_zero == 0ULL,
              "the gate reads a COMMITTED 0, not its 1ULL default");

        for (uint64_t h = 1; h <= 3; h++) {
            uint64_t minted = 123;
            CHECK(nodus_witness_v2_emission_apply(w, h, &minted) == 0 &&
                  minted == 0,
                  "emission is OFF from genesis — no height mints");
        }
        CHECK(q1(w->db, "SELECT total_minted FROM supply_tracking "
                        "WHERE id = 1") == 0,
              "and supply_tracking never moved");
        close_chain(w);
        cfg_free(&c);
        rmrf(dir);
    }
    OK();

    /* ── deferred start ────────────────────────────────────────────── */
    {
        const uint64_t START = 4ULL;
        char dir[128];
        CHECK(mkdir_tmp(dir, "i4") == 0, "tmpdir");
        OK();
        cfgbox_t c;
        CHECK(cfg_make(&c, 0x00, START) == 0, "cfg start=4");
        CHECK(nodus_witness_v2_gen_derive(dir, c.cfg, NULL) == 0, "derive");
        OK();
        nodus_witness_t *w = open_chain(dir);
        CHECK(w != NULL, "open");
        OK();

        uint64_t got_start = 0;
        CHECK(nodus_chain_config_get_u64(
                  w, (uint8_t)DNAC_CFG_INFLATION_START_BLOCK, 0,
                  UINT64_MAX, &got_start) == 0 && got_start == START,
              "the committed start is what the gate reads");

        for (uint64_t h = 1; h < START; h++) {
            uint64_t minted = 123;
            CHECK(nodus_witness_v2_emission_apply(w, h, &minted) == 0 &&
                  minted == 0, "nothing mints BELOW the committed start");
        }
        {
            uint64_t minted = 0;
            CHECK(nodus_witness_v2_emission_apply(w, START, &minted) == 0 &&
                  minted == nodus_emission_per_block(START),
                  "and the committed start height mints the scheduled "
                  "amount — the value is honoured, not merely stored");
            CHECK(q1(w->db, "SELECT total_minted FROM supply_tracking "
                            "WHERE id = 1") == (int64_t)minted,
                  "and supply_tracking recorded exactly that");
        }
        close_chain(w);
        cfg_free(&c);
        rmrf(dir);
    }
    return g_fail;
}

/* ════════════════════════════════════════════════════════════════════
 * §4 — THE FAZ 1 DETERMINISM TWIN STILL HOLDS
 * ══════════════════════════════════════════════════════════════════ */

/* Two independent derivations of the SAME config must produce the same
 * chain id AND the same whole-database logical state. Block 2C adds four
 * rows to a table that a whole-DB digest sees, so this is not a formality:
 * `created_at_unix` is pinned to 0 and `tx_hash` to source_commit
 * precisely so this still passes.
 *
 * MUTANT KILLED: write time(NULL) into created_at_unix (the shape the
 * legacy settlement path uses at bft.c:3062) — the chain ids still match,
 * because created_at_unix reaches no merkle leaf, but the digests diverge
 * and the twin fails. That is exactly the class of defect a chain-id-only
 * assertion would miss. */
static int t_determinism_twin(void) {
    char d1[128], d2[128];
    CHECK(mkdir_tmp(d1, "t1") == 0 && mkdir_tmp(d2, "t2") == 0, "tmpdirs");
    OK();

    cfgbox_t c1, c2;
    CHECK(cfg_make(&c1, 0x00, 4ULL) == 0, "cfg 1");
    CHECK(cfg_make(&c2, 0x00, 4ULL) == 0, "cfg 2 (independent, identical)");
    OK();

    uint8_t id1[32], id2[32];
    CHECK(nodus_witness_v2_gen_derive(d1, c1.cfg, id1) == 0, "derive 1");
    CHECK(nodus_witness_v2_gen_derive(d2, c2.cfg, id2) == 0, "derive 2");
    OK();
    CHECK(memcmp(id1, id2, 32) == 0,
          "identical configs derive an identical chain id");

    nodus_witness_t *w1 = open_chain(d1);
    nodus_witness_t *w2 = open_chain(d2);
    CHECK(w1 && w2, "open both twins");
    OK();

    uint8_t h1[64], h2[64];
    CHECK(db_digest(w1->db, h1) == 0 && db_digest(w2->db, h2) == 0,
          "digest both");
    CHECK(memcmp(h1, h2, 64) == 0,
          "and byte-identical whole-database logical state — including "
          "the four committed economic rows");

    /* The economic rows are IN that digest, so the assertion above is
     * really about them too — prove they are present rather than assuming
     * the digest covered them. */
    CHECK(q1(w1->db, "SELECT COUNT(*) FROM chain_config_history") == 4 &&
          q1(w2->db, "SELECT COUNT(*) FROM chain_config_history") == 4,
          "both twins carry exactly the four economic rows");
    CHECK(q1(w1->db, "SELECT COUNT(*) FROM chain_config_history "
                     "WHERE created_at_unix != 0") == 0,
          "created_at_unix is pinned to 0 — no wall clock in a committed "
          "genesis row");

    close_chain(w1);
    close_chain(w2);
    cfg_free(&c1); cfg_free(&c2);
    rmrf(d1); rmrf(d2);
    return g_fail;
}

/* ════════════════════════════════════════════════════════════════════ */

int main(void) {
    printf("=== O15J Faz 2 Block 2C — committed economic parameters ===\n");

    struct { const char *name; int (*fn)(void); } tests[] = {
        { "§1.1 path A: a changed parameter is a changed chain id",
          t_path_a_chain_id },
        { "§1.2 path A: the encoding carries every parameter",
          t_path_a_encoding },
        { "§1.3 path B: the committed rows move chain_config_root",
          t_path_b_committed_root },
        { "§2.1 derive refuses a mismatched build",
          t_derive_refuses_mismatch },
        { "§2.2 the runtime refuses a mismatched committed band",
          t_join_refuses_mismatch },
        { "§2.3 a pre-2C chain is unchanged",
          t_preexisting_chain_unchanged },
        { "§3   the inflation start is honoured from genesis",
          t_inflation_start_from_genesis },
        { "§4   the determinism twin still holds",
          t_determinism_twin },
    };

    int rc = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        printf("-- %s\n", tests[i].name);
        if (tests[i].fn() != 0) rc = 1;
    }

    printf("=== %s (%d checks) ===\n", rc ? "FAILED" : "PASSED", g_checks);
    return rc;
}
