/**
 * Nodus — Ledger V2 execution season: the ENGINE-LEVEL adversarial
 * matrix of the typed runtime execution path (INACTIVE layer).
 *
 * What lives HERE (everything else has an owner already —
 * test_v2_apply: phases/faults/rollback/quotas/supply;
 * test_v2_effects: adapter + mediated-read unit matrix;
 * test_res_meter: metering arithmetic/lifecycle; test_domreg: admission
 * quota wraparound; test_domain_runtime: table + policy pins):
 *
 *   1. epoch derivation: the block-count formula's boundary matrix +
 *      the engine's genesis/epoch gates (no wall clock anywhere).
 *   2. the fail-closed local-index helper (never aliases index 0).
 *   3. frozen-snapshot runtime resolution: per-axis mismatch, stale
 *      ruleset substitution, unregistered/inactive domains, missing
 *      exec hook, READ-access legs, runtime_op ownership.
 *   4. metering authority: the SYSTEM-committed policy is THE price —
 *      a leg-runtime decoy policy cannot reprice, a mutated/mismatched
 *      SYSTEM policy is a NODE FAULT (-2), the legacy tx_cost hook is
 *      inert, per-domain exact-fit/one-unit-short, read charges are
 *      exact.
 *   5. mediated reads through the engine: canonical order, duplicates,
 *      over-plan, and a later envelope OBSERVING an earlier envelope's
 *      canonical mutation inside the same block transaction.
 *   6. hostile runtime results: garbage bytes, unknown effect op,
 *      precondition failure, actual-over-declared effects, duplicate
 *      derived tx ids — all VERDICTS (-1); rogue adapter statuses and
 *      storage faults — NODE FAULTS (-2). Both leave the database
 *      byte-identical (digest-proven).
 *   7. determinism: twin fixtures running the same sequence land on
 *      byte-identical roots; a restart reproduces them.
 *
 * @file test_v2_exec.c
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_roots_v2.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/domain_wire.h"
#include "crypto/hash/qgp_sha3.h"

#include "v2_exec_fixture.h"
#include "v2_genesis_fixture.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

/* ── fixture (the test_v2_apply shape) ─────────────────────────────── */
static void rmrf(const char *path) {
    DIR *d = opendir(path);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 ||
                strcmp(ent->d_name, "..") == 0) continue;
            char child[1024];
            snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
            struct stat st;
            if (lstat(child, &st) == 0) {
                if (S_ISDIR(st.st_mode)) rmrf(child);
                else (void)unlink(child);
            }
        }
        closedir(d);
        (void)rmdir(path);
    } else {
        (void)unlink(path);
    }
}

typedef struct {
    nodus_witness_t *w;
    char             dir[256];
    uint8_t          chain_id16[16];
} fixture_t;

static int fx_open(fixture_t *fx) {
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_exec_XXXXXX");
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain_id16, 0x44, sizeof(fx->chain_id16));
    if (nodus_witness_create_chain_db(fx->w, fx->chain_id16) != 0) {
        rmrf(fx->dir); free(fx->w); fx->w = NULL;
        return -1;
    }
    nodus_chain_config_db_migrate(fx->w);
    return 0;
}

static int fx_reopen(fixture_t *fx) {
    const nodus_domain_runtime_t *tbl = fx->w->v2_runtime_table;
    size_t tbl_n = fx->w->v2_runtime_table_n;
    sqlite3_close(fx->w->db);
    fx->w->db = NULL;
    int rc = nodus_witness_create_chain_db(fx->w, fx->chain_id16);
    fx->w->v2_runtime_table = tbl;
    fx->w->v2_runtime_table_n = tbl_n;
    return rc;
}

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) { sqlite3_close(fx->w->db); fx->w->db = NULL; }
    free(fx->w);
    fx->w = NULL;
    rmrf(fx->dir);
}

static int run_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL failed: %s\n", err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

/* full-DB digest (the rollback oracle — test_v2_apply's shape) */
typedef struct { uint8_t *buf; size_t len, cap; } dyn_t;

static int dyn_put(dyn_t *d, const void *p, size_t n) {
    if (d->len + n > d->cap) {
        size_t nc = d->cap ? d->cap * 2 : 65536;
        while (nc < d->len + n) nc *= 2;
        uint8_t *nb = realloc(d->buf, nc);
        if (!nb) return -1;
        d->buf = nb; d->cap = nc;
    }
    memcpy(d->buf + d->len, p, n);
    d->len += n;
    return 0;
}

static int db_state_digest(nodus_witness_t *w, uint8_t out[64]) {
    sqlite3_stmt *ts = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT name FROM sqlite_master WHERE type='table' AND "
            "name NOT LIKE 'sqlite_%' ORDER BY name", -1, &ts, NULL)
        != SQLITE_OK)
        return -1;
    dyn_t d = { 0 };
    int rc, out_rc = -1;
    while ((rc = sqlite3_step(ts)) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(ts, 0);
        if (dyn_put(&d, name, strlen(name) + 1) != 0) goto done;
        char sql[256];
        snprintf(sql, sizeof(sql), "SELECT * FROM \"%s\" ORDER BY rowid",
                 name);
        sqlite3_stmt *rs = NULL;
        if (sqlite3_prepare_v2(w->db, sql, -1, &rs, NULL) != SQLITE_OK)
            goto done;
        int rrc;
        while ((rrc = sqlite3_step(rs)) == SQLITE_ROW) {
            int nc = sqlite3_column_count(rs);
            for (int c = 0; c < nc; c++) {
                uint8_t t = (uint8_t)sqlite3_column_type(rs, c);
                if (dyn_put(&d, &t, 1) != 0) { sqlite3_finalize(rs); goto done; }
                if (t == SQLITE_NULL) continue;
                const void *b = sqlite3_column_blob(rs, c);
                int bl = sqlite3_column_bytes(rs, c);
                uint32_t bl32 = (uint32_t)bl;
                if (dyn_put(&d, &bl32, 4) != 0 ||
                    (bl > 0 && dyn_put(&d, b, (size_t)bl) != 0)) {
                    sqlite3_finalize(rs);
                    goto done;
                }
            }
        }
        sqlite3_finalize(rs);
        if (rrc != SQLITE_DONE) goto done;
    }
    if (rc != SQLITE_DONE) goto done;
    out_rc = qgp_sha3_512(d.buf ? d.buf : (const uint8_t *)"", d.len, out)
                 == 0 ? 0 : -1;
done:
    sqlite3_finalize(ts);
    free(d.buf);
    return out_rc;
}

static void mk_id(uint8_t out[64], uint8_t fill) { memset(out, fill, 64); }

static void mk_block(nodus_v2_block_t *b, uint64_t h,
                     const nodus_v2_envelope_t *envs, size_t n) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = nodus_v2_epoch_for_height(h);
    /* O14 leader mode: identity is DERIVED, never carried. */
    b->envs = envs;
    b->n_envs = n;
}

static uint64_t q1(nodus_witness_t *w, const char *sql) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return UINT64_MAX;
    uint64_t v = UINT64_MAX;
    if (sqlite3_step(st) == SQLITE_ROW)
        v = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

/* reject with digest proof; accepts BOTH classes but returns which */
static int apply_reject(nodus_witness_t *w, nodus_v2_block_t *b,
                        int *rc_out) {
    uint8_t d0[64], d1[64];
    if (db_state_digest(w, d0) != 0) return 1;
    int rc = nodus_witness_v2_apply_block(w, b);
    if (rc_out) *rc_out = rc;
    if (rc != -1 && rc != -2) return 1;
    if (db_state_digest(w, d1) != 0) return 1;
    return memcmp(d0, d1, 64) != 0;
}

/* shared genesis: migrate + scripted table + v2 genesis */
static int fx_genesis(fixture_t *fx) {
    if (fx_open(fx) != 0) return -1;
    if (nodus_witness_db_migrate_v2s9(fx->w) != 0) return -1;
    if (v2x_table_init(fx->w) != 0) return -1;
    uint8_t vset[64];
    mk_id(vset, 0x77);
    /* O14: the genesis BlockID is DERIVED by the engine, not chosen. */
    return v2x_genesis_min(fx->w, vset, NULL, NULL);
}

/* one CORE UTXO CREATE envelope with an arbitrary key byte + amount */
static int env_utxo(v2x_env_t *e, uint8_t keylast, uint64_t amount) {
    uint8_t key[64] = { 0 };
    key[63] = keylast;
    uint8_t val[8];
    v2x_put64(val, amount);
    return v2x_env1(e, 1, 1, V2X_OP_UTXO, DNA_EFFECT_CREATE,
                    DNA_EFFECT_PRE_ABSENT, key, 64, val, 8);
}

/* ══ 1. epoch derivation: block count, never a clock ════════════════ */
static int test_epoch(void) {
    const uint64_t L = (uint64_t)DNAC_EPOCH_LENGTH;
    /* the boundary matrix of the consensus convention: genesis height 0
     * is epoch 0; the first boundary is L itself (height % L == 0) */
    CHECK(nodus_v2_epoch_for_height(0) == 0, "h0");
    CHECK(nodus_v2_epoch_for_height(1) == 0, "h1");
    CHECK(nodus_v2_epoch_for_height(L - 1) == 0, "hL-1");
    CHECK(nodus_v2_epoch_for_height(L) == 1, "hL");
    CHECK(nodus_v2_epoch_for_height(L + 1) == 1, "hL+1");
    CHECK(nodus_v2_epoch_for_height(2 * L - 1) == 1, "h2L-1");
    CHECK(nodus_v2_epoch_for_height(2 * L) == 2, "h2L");
    CHECK(nodus_v2_epoch_for_height(UINT64_MAX) == UINT64_MAX / L,
          "top of the range");
    OK();

    /* engine gates: genesis epoch must be the DERIVATION of height 0;
     * a block's declared epoch must be the derivation of its height */
    fixture_t fx;
    CHECK(fx_genesis(&fx) == 0, "genesis");
    static v2x_env_t e1;
    CHECK(env_utxo(&e1, 0x01, 5) == 0, "env");
    nodus_v2_envelope_t v1 = { e1.bytes, e1.len };
    nodus_v2_block_t b;
    mk_block(&b, 1, &v1, 1);
    b.epoch = 7;                        /* height 1 is epoch 0           */
    int rc = 0;
    CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
          "lying epoch accepted"); OK();
    mk_block(&b, 1, &v1, 1);            /* derived epoch: applies        */
    CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
          "derived epoch rejected"); OK();
    fx_close(&fx);
    return 0;
}

/* ══ 2. the fail-closed local-index helper ══════════════════════════ */
static int test_local_index(void) {
    uint8_t ids[3][64];
    memset(ids[0], 0x11, 64);
    memset(ids[1], 0x22, 64);
    memset(ids[2], 0x33, 64);
    uint8_t probe[64];
    uint32_t lidx = 0xDEAD;
    memset(probe, 0x22, 64);
    CHECK(nodus_witness_v2_local_index_find((const uint8_t (*)[64])ids,3, probe, &lidx) == 0 &&
          lidx == 1, "hit index 1"); OK();
    memset(probe, 0x33, 64);
    CHECK(nodus_witness_v2_local_index_find((const uint8_t (*)[64])ids,3, probe, &lidx) == 0 &&
          lidx == 2, "hit index 2"); OK();
    /* THE pin: a miss FAILS and never aliases index 0 */
    memset(probe, 0x44, 64);
    lidx = 0xDEAD;
    CHECK(nodus_witness_v2_local_index_find((const uint8_t (*)[64])ids,3, probe, &lidx) == -1,
          "miss did not fail closed");
    CHECK(lidx == 0xDEAD, "miss wrote an index"); OK();
    CHECK(nodus_witness_v2_local_index_find((const uint8_t (*)[64])ids,0, probe, &lidx) == -1,
          "empty list"); OK();
    CHECK(nodus_witness_v2_local_index_find(NULL, 3, probe, &lidx) == -1 &&
          nodus_witness_v2_local_index_find((const uint8_t (*)[64])ids,3, NULL, &lidx) == -1 &&
          nodus_witness_v2_local_index_find((const uint8_t (*)[64])ids,3, probe, NULL) == -1,
          "NULL args"); OK();
    return 0;
}

/* a read_plan that over-fills its request array (writes max+1) — the
 * one shape the scripted fixture cannot express, since v2x_script_split
 * caps at build time. Reaches the engine's post-plan count guard. */
static int overplan_read_plan(const nodus_domain_runtime_t *rt,
                              const dna_env_view_t *env, uint16_t leg,
                              const nodus_rt_exec_ctx_t *ctx,
                              nodus_rt_read_req_t *reqs, uint16_t max_reqs,
                              uint16_t *n_out) {
    (void)rt; (void)env; (void)leg; (void)ctx; (void)reqs;
    *n_out = (uint16_t)(max_reqs + 1);   /* claims more than it may */
    return 0;
}

/* ══ 3. frozen-snapshot resolution + execution admission ════════════ */
static int test_resolution(void) {
    fixture_t fx;
    CHECK(fx_genesis(&fx) == 0, "genesis");
    static v2x_env_t e1;
    CHECK(env_utxo(&e1, 0x01, 5) == 0, "env");
    nodus_v2_envelope_t v1 = { e1.bytes, e1.len };
    nodus_v2_block_t b;
    int rc;

    /* unregistered domain: a leg addressing domain 99 has no ruleset
     * entry in the snapshot — the caller cannot widen the table */
    {
        static v2x_env_t e99;
        uint8_t key[64] = { 0 };
        key[63] = 1;
        uint8_t val[8] = { 0 };
        CHECK(v2x_env1(&e99, 99, 1, V2X_OP_UTXO, DNA_EFFECT_CREATE,
                       DNA_EFFECT_PRE_ABSENT, key, 64, val, 8) == 0,
              "e99");
        nodus_v2_envelope_t v99 = { e99.bytes, e99.len };
        mk_block(&b, 1, &v99, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "unregistered domain executed"); OK();
    }

    /* stale ruleset substitution: an envelope built against
     * ruleset_version 2 cannot resolve when the committed manifest says
     * 1 — the POSITIONAL context match rejects it */
    {
        static v2x_env_t es;
        uint8_t key[64] = { 0 };
        key[63] = 2;
        uint8_t val[8] = { 0 };
        uint8_t call[600];
        uint8_t res[256];
        size_t rl = 0;
        CHECK(v2x_eff1(res, sizeof(res), V2X_OP_UTXO, DNA_EFFECT_CREATE,
                       DNA_EFFECT_PRE_ABSENT, key, 64, val, 8, &rl) == 0,
              "res");
        uint32_t cl = v2x_script_build(call, sizeof(call), NULL, 0, res,
                                       rl);
        CHECK(cl != 0, "call");
        dna_env_leg_in_t leg;
        memset(&leg, 0, sizeof(leg));
        leg.hdr.domain_id = 1;
        leg.hdr.runtime_op = 1;
        leg.hdr.ruleset_version = 1;     /* NOT the committed version —
                                          * the RETIRED pre-burn-season
                                          * CORE v1 resolves nothing     */
        leg.hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
        leg.hdr.auth_kind = 1;
        leg.hdr.call_len = cl;
        leg.hdr.auth_len = 1;
        leg.hdr.res_max_effects = 4;
        leg.hdr.res_max_effect_bytes = 2048;
        static const uint8_t auth = 0xAA;
        leg.call_data = call;
        leg.auth_data = &auth;
        dna_env_in_t in;
        memset(&in, 0, sizeof(in));
        in.res_max_total_units = 200000;
        in.leg_count = 1;
        in.legs = &leg;
        CHECK(dna_env_encode(&in, es.bytes, sizeof(es.bytes), &es.len)
                  == 0, "encode");
        nodus_v2_envelope_t vs = { es.bytes, es.len };
        mk_block(&b, 1, &vs, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "stale ruleset executed"); OK();
    }

    /* per-axis runtime mismatch: corrupt the committed manifest's
     * ruleset_hash — the five-axis lookup must MISS and the strict
     * ACTIVE preconditions fail the node closed */
    {
        dna_domain_manifest_t man;
        dna_domreg_record_t rec;
        CHECK(nodus_witness_domreg_get(fx.w, 1, &rec, &man, NULL) == 0,
              "get");
        dna_domain_manifest_t bad = man;
        bad.ruleset_hash[0] ^= 1;
        uint8_t enc[DNA_DOMMAN_MAX_ENC_LEN], mh[64];
        size_t el = 0;
        CHECK(dna_domman_encode(&bad, enc, sizeof(enc), &el) == 0 &&
              dna_domman_hash(&bad, mh) == 0, "enc");
        dna_domreg_record_t recb = rec;
        memcpy(recb.current_manifest_hash, mh, 64);
        uint8_t rb[DNA_DOMREG_REC_ENC_LEN];
        CHECK(dna_domreg_record_encode(&recb, rb) == 0, "recb");
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "UPDATE domain_registry SET record=?1, current_manifest=?2 "
              "WHERE domain_id=1", -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, rb, sizeof(rb), SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 2, enc, (int)el, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "update");
        sqlite3_finalize(st);

        mk_block(&b, 1, &v1, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -2,
              "hash-mismatched runtime resolved (must be a node FAULT)");
        OK();

        /* restore */
        uint8_t enc0[DNA_DOMMAN_MAX_ENC_LEN], mh0[64];
        size_t el0 = 0;
        CHECK(dna_domman_encode(&man, enc0, sizeof(enc0), &el0) == 0 &&
              dna_domman_hash(&man, mh0) == 0, "enc0");
        memcpy(recb.current_manifest_hash, mh0, 64);
        CHECK(dna_domreg_record_encode(&recb, rb) == 0, "rb0");
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "UPDATE domain_registry SET record=?1, current_manifest=?2 "
              "WHERE domain_id=1", -1, &st, NULL) == SQLITE_OK, "prep0");
        sqlite3_bind_blob(st, 1, rb, sizeof(rb), SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 2, enc0, (int)el0, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "restore");
        sqlite3_finalize(st);
    }

    /* missing exec hook: the PRODUCTION builtin table has no execution
     * surface — the same block fails closed as a VERDICT (the domain
     * resolves, it just cannot execute envelope legs) */
    {
        const nodus_domain_runtime_t *tbl = fx.w->v2_runtime_table;
        size_t n = fx.w->v2_runtime_table_n;
        fx.w->v2_runtime_table = NULL;   /* builtin table               */
        fx.w->v2_runtime_table_n = 0;
        mk_block(&b, 1, &v1, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "exec-less runtime executed"); OK();
        fx.w->v2_runtime_table = tbl;
        fx.w->v2_runtime_table_n = n;
    }

    /* READ-access legs are rejected this season (fail-closed) */
    {
        static v2x_env_t er;
        uint8_t res[64];
        size_t rl = 0;
        CHECK(dna_effect_result_encode(NULL, 0, res, sizeof(res), &rl)
                  == 0, "empty res");
        uint8_t call[128];
        uint32_t cl = v2x_script_build(call, sizeof(call), NULL, 0, res,
                                       rl);
        CHECK(cl != 0, "call");
        dna_env_leg_in_t leg;
        memset(&leg, 0, sizeof(leg));
        leg.hdr.domain_id = 1;
        leg.hdr.runtime_op = 1;
        leg.hdr.ruleset_version = 1;
        leg.hdr.access_mode = DNA_ENV_ACCESS_READ;
        leg.hdr.auth_kind = 1;
        leg.hdr.call_len = cl;
        leg.hdr.auth_len = 1;
        leg.hdr.res_max_effects = 0;
        leg.hdr.res_max_effect_bytes = 64;
        static const uint8_t auth = 0xAA;
        leg.call_data = call;
        leg.auth_data = &auth;
        dna_env_in_t in;
        memset(&in, 0, sizeof(in));
        in.res_max_total_units = 200000;
        in.leg_count = 1;
        in.legs = &leg;
        CHECK(dna_env_encode(&in, er.bytes, sizeof(er.bytes), &er.len)
                  == 0, "encode");
        nodus_v2_envelope_t vr = { er.bytes, er.len };
        mk_block(&b, 1, &vr, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "READ leg executed"); OK();
    }

    /* runtime_op OWNERSHIP GATE — isolated.
     *
     * The gate (rt_owns_runtime_op vs the committed descriptor rule_ids)
     * sits AFTER preflight+reserve, so an op that is not PRICED by the
     * SYSTEM policy dies earlier at plan-build (ERR_OP_WEIGHT) and never
     * reaches the gate. With the shipped config priced=={1..6}==owned,
     * so no envelope built against the real descriptors can exercise
     * ownership in isolation. This white-box fixture SHRINKS CORE's
     * ownership set to {1} while leaving the SYSTEM policy pricing 1..6:
     * a leg invoking op 2 is therefore PRICED (passes plan-build) but
     * NOT OWNED — only the ownership gate can reject it. (Resolution
     * matches on the five-axis tuple incl. ruleset_hash, which is
     * unchanged; runtime_for does not re-hash the descriptor, so
     * narrowing rule_ids alone reaches the gate.) */
    {
        static nodus_domain_runtime_t narrow_tbl[2];
        static const uint32_t core_one_rule[1] = { 1 };
        memcpy(narrow_tbl, g_v2x_table, sizeof(narrow_tbl));
        narrow_tbl[1].descriptor.rule_count = 1;
        narrow_tbl[1].descriptor.rule_ids = core_one_rule;
        fx.w->v2_runtime_table = narrow_tbl;
        fx.w->v2_runtime_table_n = 2;
        static v2x_env_t eo;
        uint8_t key[64] = { 0 };
        key[63] = 3;
        uint8_t val[8] = { 0 };
        /* op 2 == V2X_OP_UTXO's runtime_op here; SYSTEM prices it,
         * shrunken CORE does not own it */
        CHECK(v2x_env1(&eo, 1, 2, V2X_OP_UTXO, DNA_EFFECT_CREATE,
                       DNA_EFFECT_PRE_ABSENT, key, 64, val, 8) == 0,
              "eo");
        nodus_v2_envelope_t vo = { eo.bytes, eo.len };
        mk_block(&b, 1, &vo, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "unowned-but-priced runtime_op executed"); OK();
        fx.w->v2_runtime_table = g_v2x_table;  /* restore shared fx    */
        fx.w->v2_runtime_table_n = 2;
        /* POSITIVE CONTROL on a FRESH fixture (keeps the shared fx
         * uncommitted): the SAME op 2 on the UNSHRUNK CORE (op 2 IS
         * owned) APPLIES — proving the reject above was the ownership
         * gate, not some incidental earlier rejection. */
        fixture_t fp;
        CHECK(fx_genesis(&fp) == 0, "genesis P");
        static v2x_env_t eok;
        CHECK(v2x_env1(&eok, 1, 2, V2X_OP_UTXO, DNA_EFFECT_CREATE,
                       DNA_EFFECT_PRE_ABSENT, key, 64, val, 8) == 0,
              "eok");
        nodus_v2_envelope_t vok = { eok.bytes, eok.len };
        nodus_v2_block_t bp;
        mk_block(&bp, 1, &vok, 1);
        CHECK(nodus_witness_v2_apply_block(fp.w, &bp) == 0,
              "owned op rejected — the gate is over-broad"); OK();
        fx_close(&fp);
    }

    /* OVER-PLAN: a read_plan that emits MORE than NODUS_RT_MAX_READS
     * requests is rejected by the engine's post-plan count guard
     * (unreachable through the scripted fixture, which caps at build
     * time — so this uses a dedicated hook). Reject on the shared fx,
     * height 1, nothing committed. */
    {
        static nodus_domain_runtime_t op_tbl[2];
        memcpy(op_tbl, g_v2x_table, sizeof(op_tbl));
        op_tbl[1].read_plan = overplan_read_plan;
        fx.w->v2_runtime_table = op_tbl;
        fx.w->v2_runtime_table_n = 2;
        static v2x_env_t eop;
        CHECK(env_utxo(&eop, 0x40, 1) == 0, "eop");
        nodus_v2_envelope_t vop = { eop.bytes, eop.len };
        mk_block(&b, 1, &vop, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "over-plan read list executed"); OK();
        fx.w->v2_runtime_table = g_v2x_table;
        fx.w->v2_runtime_table_n = 2;
    }

    /* duplicate DERIVED identity: the same bytes twice in one block */
    {
        nodus_v2_envelope_t two[2] = {
            { e1.bytes, e1.len }, { e1.bytes, e1.len }
        };
        mk_block(&b, 1, two, 2);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "duplicate derived tx_id accepted"); OK();
    }
    fx_close(&fx);
    return 0;
}

/* ══ 4. metering authority ══════════════════════════════════════════ */

/* a decoy policy with WILDLY different weights, correctly sealed */
static dna_meter_policy_t g_decoy_policy;

static int decoy_policy_build(void) {
    memset(&g_decoy_policy, 0, sizeof(g_decoy_policy));
    g_decoy_policy.policy_version = DNA_METER_POLICY_VERSION;
    g_decoy_policy.w_base = 999;
    g_decoy_policy.w_callbyte = 999;
    g_decoy_policy.w_authbyte = 999;
    g_decoy_policy.w_effect = 999;
    g_decoy_policy.w_effectbyte = 999;
    g_decoy_policy.w_read = 999;
    g_decoy_policy.w_write = 999;
    g_decoy_policy.max_block_env_bytes = 999999;   /* policy v2 field   */
    for (uint32_t op = 1; op <= 6; op++)
        if (dna_meter_op_set(&g_decoy_policy, op, 999) != 0) return -1;
    return dna_meter_policy_seal(&g_decoy_policy);
}

/* a tx_cost hook declaring absurd work units — must be INERT */
static int absurd_cost(const nodus_domain_runtime_t *rt, uint8_t tx_type,
                       uint32_t *cost_out) {
    (void)rt; (void)tx_type;
    *cost_out = 4000000u;
    return 0;
}

static int test_meter_authority(void) {
    CHECK(decoy_policy_build() == 0, "decoy policy");

    /* Baseline: apply one block, record the committed consumed units. */
    fixture_t fa;
    CHECK(fx_genesis(&fa) == 0, "genesis A");
    static v2x_env_t e1;
    CHECK(env_utxo(&e1, 0x01, 5) == 0, "env");
    nodus_v2_envelope_t v1 = { e1.bytes, e1.len };
    nodus_v2_block_t b;
    mk_block(&b, 1, &v1, 1);
    CHECK(nodus_witness_v2_apply_block(fa.w, &b) == 0, "baseline");
    uint8_t base_root[64];
    memcpy(base_root, b.out_global_root, 64);
    /* the committed consumed units: every weight is 1 and there are no
     * reads, so consumed = (w_op 1 + call_len + auth 1) + (1 eff +
     * res_len) — read back from the DomainUpdate */
    uint64_t base_units;
    {
        sqlite3_stmt *st = NULL;
        /* O15J Faz 2 review R2-F8 — the query used to be
         *   "... WHERE global_height=1"
         * with NO domain filter and NO ORDER BY, then took the first row.
         * That was already an unordered read of a consensus table inside
         * a test whose whole purpose is to pin determinism; it only
         * happened to return SYSTEM's row. Once emission makes every
         * block produce a CORE update too, it can return CORE's
         * (res_verify_cost == 0) and the arithmetic below fails.
         *
         * The ORCHESTRATOR's first response was to quiet this whole file
         * — justified in a comment claiming "emission adds work to every
         * block". That is FALSE: emission consumes ZERO metered units
         * (nodus_witness_v2_econ.c uses direct DB helpers; the typed
         * effect path has no meter interaction). Quieting deleted
         * metering coverage on the configuration production actually
         * runs, to work around a defect in the query. Naming the domain
         * is the actual fix. */
        CHECK(sqlite3_prepare_v2(fa.w->db,
              "SELECT upd FROM v2_domain_updates "
              "WHERE global_height = 1 AND domain_id = ?1",
              -1, &st, NULL) == SQLITE_OK &&
              /* The envelope targets CORE (env_utxo -> v2x_env1 domain 1).
               * "SYSTEM-policy arithmetic" below names the METERING
               * POLICY's owner, not the touched domain — the units being
               * checked are CORE's DomainUpdate. */
              sqlite3_bind_int64(st, 1, (sqlite3_int64)DNA_DOMAIN_CORE)
                  == SQLITE_OK &&
              sqlite3_step(st) == SQLITE_ROW,
              "upd");
        dna_domain_update_t u;
        CHECK(dna_dupd_decode(sqlite3_column_blob(st, 0),
                              (size_t)sqlite3_column_bytes(st, 0), &u)
                  == 0, "dec");
        sqlite3_finalize(st);
        base_units = u.res_verify_cost;
        dna_env_view_t vv;
        CHECK(dna_env_decode(e1.bytes, e1.len, &vv) == 0, "dec env");
        uint64_t call_len = vv.leg[0].call_len;
        CHECK(base_units == (1 + call_len + 1) + (1 + (call_len - 2)),
              "baseline units are not the SYSTEM-policy arithmetic");
        OK();
    }
    fx_close(&fa);

    /* A LEG-DOMAIN DECOY POLICY cannot reprice: CORE carries a sealed
     * 999-weight policy, yet the same block commits the same root and
     * the same consumed units — the SYSTEM snapshot is the ONLY price
     * authority. */
    {
        fixture_t fb;
        CHECK(fx_genesis(&fb) == 0, "genesis B");
        static nodus_domain_runtime_t decoy_tbl[2];
        memcpy(decoy_tbl, g_v2x_table, sizeof(decoy_tbl));
        decoy_tbl[1].meter_policy = &g_decoy_policy;
        fb.w->v2_runtime_table = decoy_tbl;
        fb.w->v2_runtime_table_n = 2;
        nodus_v2_block_t b2;
        mk_block(&b2, 1, &v1, 1);
        CHECK(nodus_witness_v2_apply_block(fb.w, &b2) == 0, "decoy block");
        CHECK(memcmp(b2.out_global_root, base_root, 64) == 0,
              "a leg-domain policy changed the committed root"); OK();
        sqlite3_stmt *st = NULL;
        /* Same unordered-read defect as the baseline capture above
         * (R2-F8): name the domain instead of taking whichever row the
         * planner returns first. */
        CHECK(sqlite3_prepare_v2(fb.w->db,
              "SELECT upd FROM v2_domain_updates "
              "WHERE global_height = 1 AND domain_id = ?1",
              -1, &st, NULL) == SQLITE_OK &&
              sqlite3_bind_int64(st, 1, (sqlite3_int64)DNA_DOMAIN_CORE)
                  == SQLITE_OK &&
              sqlite3_step(st) == SQLITE_ROW,
              "upd");
        dna_domain_update_t u;
        CHECK(dna_dupd_decode(sqlite3_column_blob(st, 0),
                              (size_t)sqlite3_column_bytes(st, 0), &u)
                  == 0, "dec");
        sqlite3_finalize(st);
        CHECK(u.res_verify_cost == base_units,
              "a leg-domain policy repriced the transaction"); OK();
        fx_close(&fb);
    }

    /* THE LEGACY tx_cost HOOK IS INERT on the envelope lane: an absurd
     * per-type declaration changes neither the verdict nor a single
     * committed byte. */
    {
        fixture_t fc;
        CHECK(fx_genesis(&fc) == 0, "genesis C");
        static nodus_domain_runtime_t cost_tbl[2];
        memcpy(cost_tbl, g_v2x_table, sizeof(cost_tbl));
        cost_tbl[1].tx_cost = absurd_cost;
        fc.w->v2_runtime_table = cost_tbl;
        fc.w->v2_runtime_table_n = 2;
        nodus_v2_block_t b3;
        mk_block(&b3, 1, &v1, 1);
        CHECK(nodus_witness_v2_apply_block(fc.w, &b3) == 0,
              "tx_cost hook leaked into the envelope lane");
        CHECK(memcmp(b3.out_global_root, base_root, 64) == 0,
              "tx_cost changed committed state"); OK();
        fx_close(&fc);
    }

    /* A SYSTEM POLICY THAT DOES NOT MATCH ITS COMMITTED IDENTITY is a
     * NODE FAULT: two validators claiming the same ruleset identity
     * cannot select different weights — this node simply cannot
     * execute. Both a decoy (sealed, wrong digest) and a corrupted
     * (right weights, broken seal) policy refuse. */
    {
        fixture_t fd;
        CHECK(fx_genesis(&fd) == 0, "genesis D");
        static nodus_domain_runtime_t bad_tbl[2];
        memcpy(bad_tbl, g_v2x_table, sizeof(bad_tbl));
        bad_tbl[0].meter_policy = &g_decoy_policy;   /* digest mismatch */
        fd.w->v2_runtime_table = bad_tbl;
        fd.w->v2_runtime_table_n = 2;
        nodus_v2_block_t b4;
        int rc;
        mk_block(&b4, 1, &v1, 1);
        CHECK(apply_reject(fd.w, &b4, &rc) == 0 && rc == -2,
              "same-identity different-weights was not a node fault");
        OK();
        /* corrupted seal (mutation after the snapshot was compiled) */
        static dna_meter_policy_t mutated;
        memcpy(&mutated, g_v2x_table[0].meter_policy, sizeof(mutated));
        mutated.w_read = 77;             /* weights moved, seal stale    */
        bad_tbl[0].meter_policy = &mutated;
        mk_block(&b4, 1, &v1, 1);
        CHECK(apply_reject(fd.w, &b4, &rc) == 0 && rc == -2,
              "mutated policy was not a node fault"); OK();
        fx_close(&fd);
    }

    /* EXACT FIT / ONE UNIT SHORT.
     *
     * PER-DOMAIN, through the engine's own reservation seam (the exact
     * budget shape the snapshot builds): the leg's static units must
     * fit the domain entry exactly — one unit short is a TYPED
     * ERR_DOMAIN_BUDGET, exact fit reserves and drains the entry to 0.
     * (An engine-level success run cannot tamper quota_verify_cost out
     * of band: rewriting the committed registry moves SYSTEM's root
     * and the untouched-domain guard rightly rejects the block — the
     * seam is where the exact statuses are observable.) */
    {
        fixture_t fe;
        CHECK(fx_genesis(&fe) == 0, "genesis E");
        dna_env_view_t vv;
        CHECK(dna_env_decode(e1.bytes, e1.len, &vv) == 0, "dec env");
        /* static(leg) under all-1 weights = w_op 1 + call_len + auth 1
         * + max_effects + max_effect_bytes */
        uint64_t stat = 1 + vv.leg[0].call_len + 1 +
                        vv.leg[0].res_max_effects +
                        vv.leg[0].res_max_effect_bytes;
        dna_domain_manifest_t sman, cman;
        CHECK(nodus_witness_domreg_get(fe.w, 0, NULL, &sman, NULL) == 0,
              "sman");
        CHECK(nodus_witness_domreg_get(fe.w, 1, NULL, &cman, NULL) == 0,
              "cman");
        dna_env_leg_ctx_t rs[2];
        rs[0].domain_id = 0;
        rs[0].ruleset_version = sman.ruleset_version;
        memcpy(rs[0].ruleset_hash, sman.ruleset_hash, 64);
        rs[1].domain_id = 1;
        rs[1].ruleset_version = cman.ruleset_version;
        memcpy(rs[1].ruleset_hash, cman.ruleset_hash, 64);
        const dna_meter_policy_t *pol = g_v2x_table[0].meter_policy;
        dna_meter_budget_t bud;
        dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
        dna_meter_t *m = calloc(1, sizeof(*m));
        CHECK(pf && m, "alloc");
        nodus_v2_envelope_t ve = { e1.bytes, e1.len };
        dna_meter_status_t ms = DNA_METER_OK;

        memset(&bud, 0, sizeof(bud));
        bud.global_remaining = NODUS_V2_GLOBAL_UNIT_BUDGET;
        bud.n_domains = 2;
        bud.dom[0].domain_id = 0;
        bud.dom[0].remaining_units = NODUS_V2_GLOBAL_UNIT_BUDGET;
        bud.dom[1].domain_id = 1;
        bud.dom[1].remaining_units = stat - 1;   /* ONE UNIT SHORT     */
        CHECK(nodus_witness_v2_env_preflight_reserve_batch(fe.w, 1, rs, 2,
                  pol, &bud, &ve, 1, pf, m, NULL, NULL, &ms)
                  == NODUS_V2_ENV_ERR_METER &&
              ms == DNA_METER_ERR_DOMAIN_BUDGET,
              "one unit short was not ERR_DOMAIN_BUDGET"); OK();
        CHECK(bud.dom[1].remaining_units == stat - 1,
              "failed reservation moved the budget"); OK();

        bud.dom[1].remaining_units = stat;       /* EXACT FIT          */
        CHECK(nodus_witness_v2_env_preflight_reserve_batch(fe.w, 1, rs, 2,
                  pol, &bud, &ve, 1, pf, m, NULL, NULL, &ms)
                  == NODUS_V2_ENV_OK, "exact fit rejected");
        CHECK(bud.dom[1].remaining_units == 0,
              "exact fit did not drain the entry"); OK();
        CHECK(dna_meter_abort(m) == DNA_METER_OK &&
              bud.dom[1].remaining_units == stat,
              "abort did not restore the exact-fit reservation"); OK();
        free(pf);
        free(m);
        fx_close(&fe);
    }

    /* GLOBAL exact fit through the ENGINE: a ceiling of exactly the
     * global unit budget reserves and commits; +1 rejects (the pair to
     * test_v2_apply's over-budget case). */
    {
        fixture_t ff;
        CHECK(fx_genesis(&ff) == 0, "genesis F");
        uint8_t key[64] = { 0 };
        key[63] = 0x31;
        uint8_t val[8];
        v2x_put64(val, 1);
        uint8_t res[256];
        size_t rl = 0;
        CHECK(v2x_eff1(res, sizeof(res), V2X_OP_UTXO, DNA_EFFECT_CREATE,
                       DNA_EFFECT_PRE_ABSENT, key, 64, val, 8, &rl) == 0,
              "res");
        uint8_t call[512];
        uint32_t cl = v2x_script_build(call, sizeof(call), NULL, 0, res,
                                       rl);
        CHECK(cl != 0, "call");
        v2x_leg_t leg = { 1, 1, call, cl, 4, 2048 };
        static v2x_env_t ex;
        CHECK(v2x_env_build_ex(&ex, NODUS_V2_GLOBAL_UNIT_BUDGET, 0, 0,
                               &leg, 1) == 0, "ex");
        nodus_v2_envelope_t vx = { ex.bytes, ex.len };
        nodus_v2_block_t bf;
        mk_block(&bf, 1, &vx, 1);
        CHECK(nodus_witness_v2_apply_block(ff.w, &bf) == 0,
              "global exact fit rejected"); OK();
        fx_close(&ff);
    }
    return 0;
}

/* ══ 5+6. mediated reads through the engine + hostile results ═══════ */

/* SUM runtime exec: reads the key named in its script (one read), then
 * CREATEs a second key whose value = read value + 1 — the read-
 * observes-earlier-mutation witness. The output key is the input key
 * with the LAST byte incremented. */
static int sum_exec(const nodus_domain_runtime_t *rt,
                    const dna_env_view_t *env, uint16_t leg,
                    const nodus_rt_exec_ctx_t *ctx,
                    const nodus_rt_read_res_t *reads, uint16_t n_reads,
                    uint8_t *res_out, size_t res_cap,
                    size_t *res_len_out) {
    (void)rt; (void)ctx;
    if (n_reads != 1 || !reads[0].present || reads[0].value_len != 8)
        return -1;
    /* recover the read key from the script to derive the output key */
    nodus_rt_read_req_t req[NODUS_RT_MAX_READS];
    uint16_t nr = 0;
    const uint8_t *tail = NULL;
    size_t tl = 0;
    if (v2x_script_split(env->buf + env->call_off[leg],
                         env->leg[leg].call_len, req, NODUS_RT_MAX_READS,
                         &nr, &tail, &tl) != 0 || nr != 1)
        return -1;
    uint8_t out_key[64];
    memcpy(out_key, req[0].key, 64);
    out_key[63] = (uint8_t)(out_key[63] + 1);
    uint64_t v = v2x_get64(reads[0].value) + 1;
    uint8_t val[8];
    v2x_put64(val, v);
    dna_effect_in_t eff;
    memset(&eff, 0, sizeof(eff));
    eff.hdr.op_id = V2X_OP_UTXO;
    eff.hdr.effect_kind = DNA_EFFECT_CREATE;
    eff.hdr.precond_tag = DNA_EFFECT_PRE_ABSENT;
    eff.hdr.key_len = 64;
    eff.hdr.value_len = 8;
    eff.key = out_key;
    eff.value = val;
    return dna_effect_result_encode(&eff, 1, res_out, res_cap,
                                    res_len_out);
}

/* rogue exec: returns garbage bytes claiming success */
static int garbage_exec(const nodus_domain_runtime_t *rt,
                        const dna_env_view_t *env, uint16_t leg,
                        const nodus_rt_exec_ctx_t *ctx,
                        const nodus_rt_read_res_t *reads,
                        uint16_t n_reads, uint8_t *res_out,
                        size_t res_cap, size_t *res_len_out) {
    (void)rt; (void)env; (void)leg; (void)ctx; (void)reads; (void)n_reads;
    (void)res_cap;
    memset(res_out, 0x5A, 64);
    *res_len_out = 64;
    return 0;
}

/* rogue mutate: answers with a precondition status (out of contract) */
static nodus_adapter_status_t rogue_mutate(
        const nodus_domain_adapter_t *ad, struct nodus_witness *w,
        uint32_t dom, const nodus_adapter_op_t *op, uint8_t kind,
        const uint8_t *key, uint16_t key_len,
        const uint8_t *value, uint32_t value_len) {
    (void)ad; (void)w; (void)dom; (void)op; (void)kind; (void)key;
    (void)key_len; (void)value; (void)value_len;
    return NODUS_ADAPTER_ERR_PRECOND_MISSING;
}

/* an envelope whose script asks ONE read of `rkey` and whose exec is
 * the SUM runtime (the tail after the read section is empty — sum_exec
 * builds its own result) */
static int env_sum_read(v2x_env_t *e, uint8_t rkey_last) {
    nodus_rt_read_req_t rd;
    memset(&rd, 0, sizeof(rd));
    rd.op_id = V2X_OP_UTXO;
    rd.key_len = 64;
    rd.key[63] = rkey_last;
    uint8_t call[256];
    uint32_t cl = v2x_script_build(call, sizeof(call), &rd, 1, NULL, 0);
    if (!cl) return -1;
    v2x_leg_t leg = { 1, 1, call, cl, 4, 2048 };
    return v2x_env_build(e, &leg, 1);
}

static int test_reads_and_hostile(void) {
    fixture_t fx;
    CHECK(fx_genesis(&fx) == 0, "genesis");
    static nodus_domain_runtime_t sum_tbl[2];
    memcpy(sum_tbl, g_v2x_table, sizeof(sum_tbl));
    sum_tbl[1].exec = sum_exec;          /* CORE executes via SUM        */
    fx.w->v2_runtime_table = sum_tbl;
    fx.w->v2_runtime_table_n = 2;

    /* seed a CORE row OUTSIDE any block (fixture state), then ONE block
     * with TWO envelopes: A creates key 0x10 = 41 (scripted runtime is
     * not in play for A — build it against the UTXO op through
     * sum_tbl[1].exec? No: A must use the SCRIPTED exec, so A goes
     * through a second table? Simpler: A also uses SUM — A reads the
     * seeded key 0x01 (value 40), creating key 0x02 = 41; B then reads
     * key 0x02 — the row A JUST created inside this same block
     * transaction — and creates key 0x03 = 42. B's success IS the
     * read-observes-earlier-canonical-mutation proof. */
    CHECK(run_sql(fx.w->db,
        "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
        "tx_hash, output_index, block_height, created_at, unlock_block, "
        "domain_id) VALUES (CAST(zeroblob(63)||x'01' AS BLOB), 'fp', 40, "
        "zeroblob(64), zeroblob(63)||x'aa', 0, 0, 0, 0, 1)") == 0,
        "seed");
    static v2x_env_t ea, eb;
    CHECK(env_sum_read(&ea, 0x01) == 0, "ea");
    CHECK(env_sum_read(&eb, 0x02) == 0, "eb");
    nodus_v2_envelope_t vab[2] = {
        { ea.bytes, ea.len }, { eb.bytes, eb.len }
    };
    nodus_v2_block_t b;
    mk_block(&b, 1, vab, 2);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0, "read chain");
    CHECK(q1(fx.w, "SELECT amount FROM utxo_set WHERE "
                   "nullifier=CAST(zeroblob(63)||x'02' AS BLOB)") == 41 &&
          q1(fx.w, "SELECT amount FROM utxo_set WHERE "
                   "nullifier=CAST(zeroblob(63)||x'03' AS BLOB)") == 42,
          "later envelope did not observe the earlier mutation"); OK();
    /* read charges are exact: consumed = fixed + effects + 1 read */
    {
        sqlite3_stmt *st = NULL;
        /* Third instance of the same unordered-read defect (R2-F8). */
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "SELECT upd FROM v2_domain_updates "
              "WHERE global_height = 1 AND domain_id = ?1",
              -1, &st, NULL) == SQLITE_OK &&
              sqlite3_bind_int64(st, 1, (sqlite3_int64)DNA_DOMAIN_CORE)
                  == SQLITE_OK &&
              sqlite3_step(st) == SQLITE_ROW,
              "upd");
        dna_domain_update_t u;
        CHECK(dna_dupd_decode(sqlite3_column_blob(st, 0),
                              (size_t)sqlite3_column_bytes(st, 0), &u)
                  == 0, "dec");
        sqlite3_finalize(st);
        dna_env_view_t vv;
        CHECK(dna_env_decode(ea.bytes, ea.len, &vv) == 0, "dec env");
        uint64_t call_len = vv.leg[0].call_len;
        /* per envelope: fixed (1 + call + 1) + 1 READ + effects
         * (1 + res_len). sum_exec emits one 8-byte-value effect over a
         * 64-byte key: res_len = 23 + 84 + 64 + 8 = 179. */
        uint64_t per = (1 + call_len + 1) + 1 + (1 + 179);
        CHECK(u.res_tx_count == 2 && u.res_verify_cost == 2 * per,
              "read charge is not exactly once per read"); OK();
    }

    /* duplicate reads reject; descending reads reject; over-plan
     * rejects — all deterministic VERDICTS */
    {
        int rc;
        nodus_rt_read_req_t rr[2];
        memset(rr, 0, sizeof(rr));
        rr[0].op_id = V2X_OP_UTXO;
        rr[0].key_len = 64;
        rr[0].key[63] = 0x01;
        rr[1] = rr[0];                   /* duplicate                    */
        uint8_t call[512];
        uint32_t cl = v2x_script_build(call, sizeof(call), rr, 2, NULL,
                                       0);
        CHECK(cl != 0, "call");
        v2x_leg_t leg = { 1, 1, call, cl, 4, 2048 };
        static v2x_env_t ed;
        CHECK(v2x_env_build(&ed, &leg, 1) == 0, "ed");
        nodus_v2_envelope_t vd = { ed.bytes, ed.len };
        mk_block(&b, 2, &vd, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "duplicate reads accepted"); OK();
        /* descending */
        rr[0].key[63] = 0x02;
        rr[1].key[63] = 0x01;
        cl = v2x_script_build(call, sizeof(call), rr, 2, NULL, 0);
        CHECK(cl != 0, "call2");
        v2x_leg_t leg2 = { 1, 1, call, cl, 4, 2048 };
        static v2x_env_t ee;
        CHECK(v2x_env_build(&ee, &leg2, 1) == 0, "ee");
        nodus_v2_envelope_t ve = { ee.bytes, ee.len };
        mk_block(&b, 2, &ve, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "descending reads accepted"); OK();
    }

    /* hostile results (scripted table again) */
    fx.w->v2_runtime_table = g_v2x_table;
    fx.w->v2_runtime_table_n = 2;
    int rc;
    {   /* garbage result bytes */
        static nodus_domain_runtime_t g_tbl[2];
        memcpy(g_tbl, g_v2x_table, sizeof(g_tbl));
        g_tbl[1].exec = garbage_exec;
        fx.w->v2_runtime_table = g_tbl;
        static v2x_env_t eg;
        CHECK(env_utxo(&eg, 0x20, 1) == 0, "eg");
        nodus_v2_envelope_t vg = { eg.bytes, eg.len };
        mk_block(&b, 2, &vg, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "garbage result applied"); OK();
        fx.w->v2_runtime_table = g_v2x_table;
    }
    {   /* SQL SMUGGLED AS A RESULT: a runtime result that is literal
         * SQL text is just malformed bytes — the engine must REJECT it
         * as a verdict and MUST NOT execute it (there is no raw-SQL
         * fallback of any kind; a mutant that "helpfully" executes the
         * bytes would commit the insert and flip this block to rc 0). */
        static const char smuggled[] =
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
            "tx_hash, output_index, block_height, created_at, "
            "unlock_block, domain_id) VALUES (CAST(zeroblob(63)||x'66' "
            "AS BLOB), 'smuggled', 0, zeroblob(64), zeroblob(63)||x'aa', "
            "0, 1, 0, 0, 1)";
        uint8_t call[512];
        uint32_t cl = v2x_script_build(call, sizeof(call), NULL, 0,
                                       (const uint8_t *)smuggled,
                                       sizeof(smuggled) - 1);
        CHECK(cl != 0, "call");
        v2x_leg_t leg = { 1, 1, call, cl, 4, 2048 };
        static v2x_env_t esql;
        CHECK(v2x_env_build(&esql, &leg, 1) == 0, "esql");
        nodus_v2_envelope_t vsql = { esql.bytes, esql.len };
        mk_block(&b, 2, &vsql, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "smuggled SQL executed"); OK();
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM utxo_set WHERE "
                       "owner='smuggled'") == 0,
              "smuggled SQL reached storage"); OK();
    }
    {   /* unknown effect op */
        static v2x_env_t eu;
        uint8_t key[64] = { 0 };
        key[63] = 0x21;
        uint8_t val[8] = { 0 };
        CHECK(v2x_env1(&eu, 1, 1, 77 /* not a CORE adapter op */,
                       DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT, key, 64,
                       val, 8) == 0, "eu");
        nodus_v2_envelope_t vu = { eu.bytes, eu.len };
        mk_block(&b, 2, &vu, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "unknown effect op applied"); OK();
    }
    {   /* precondition failure: CREATE over the existing key 0x01 */
        static v2x_env_t ep;
        CHECK(env_utxo(&ep, 0x01, 9) == 0, "ep");
        nodus_v2_envelope_t vp = { ep.bytes, ep.len };
        mk_block(&b, 2, &vp, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "failed precondition applied"); OK();
    }
    {   /* actual effects above the DECLARED per-leg ceiling */
        uint8_t key[64] = { 0 };
        key[63] = 0x22;
        uint8_t val[8] = { 0 };
        uint8_t res[256];
        size_t rl = 0;
        CHECK(v2x_eff1(res, sizeof(res), V2X_OP_UTXO, DNA_EFFECT_CREATE,
                       DNA_EFFECT_PRE_ABSENT, key, 64, val, 8, &rl) == 0,
              "res");
        uint8_t call[512];
        uint32_t cl = v2x_script_build(call, sizeof(call), NULL, 0, res,
                                       rl);
        CHECK(cl != 0, "call");
        v2x_leg_t leg = { 1, 1, call, cl, 0 /* declares ZERO effects */,
                          2048 };
        static v2x_env_t el;
        CHECK(v2x_env_build(&el, &leg, 1) == 0, "el");
        nodus_v2_envelope_t vl = { el.bytes, el.len };
        mk_block(&b, 2, &vl, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -1,
              "over-declaration applied"); OK();
    }
    {   /* rogue adapter status: NODE FAULT, digest-proven no-op */
        static nodus_domain_adapter_t rogue_ad;
        memcpy(&rogue_ad, &V2X_CORE_ADAPTER, sizeof(rogue_ad));
        rogue_ad.mutate = rogue_mutate;
        static nodus_domain_runtime_t r_tbl[2];
        memcpy(r_tbl, g_v2x_table, sizeof(r_tbl));
        r_tbl[1].adapter = &rogue_ad;
        fx.w->v2_runtime_table = r_tbl;
        static v2x_env_t er;
        CHECK(env_utxo(&er, 0x23, 1) == 0, "er");
        nodus_v2_envelope_t vr = { er.bytes, er.len };
        mk_block(&b, 2, &vr, 1);
        CHECK(apply_reject(fx.w, &b, &rc) == 0 && rc == -2,
              "rogue adapter status was not a node fault"); OK();
        fx.w->v2_runtime_table = g_v2x_table;
    }
    fx_close(&fx);
    return 0;
}

/* ══ 7. determinism: twins + restart ════════════════════════════════ */
static int test_determinism(void) {
    fixture_t fa, fb;
    CHECK(fx_genesis(&fa) == 0, "genesis A");
    CHECK(fx_genesis(&fb) == 0, "genesis B");
    static v2x_env_t e1, e2;
    CHECK(env_utxo(&e1, 0x01, 5) == 0, "e1");
    CHECK(env_utxo(&e2, 0x02, 7) == 0, "e2");
    nodus_v2_envelope_t v12[2] = {
        { e1.bytes, e1.len }, { e2.bytes, e2.len }
    };
    nodus_v2_block_t ba, bb;
    mk_block(&ba, 1, v12, 2);
    mk_block(&bb, 1, v12, 2);
    CHECK(nodus_witness_v2_apply_block(fa.w, &ba) == 0, "A");
    CHECK(nodus_witness_v2_apply_block(fb.w, &bb) == 0, "B");
    CHECK(memcmp(ba.out_global_root, bb.out_global_root, 64) == 0 &&
          memcmp(ba.out_tx_root, bb.out_tx_root, 64) == 0 &&
          memcmp(ba.out_dupd_root, bb.out_dupd_root, 64) == 0,
          "twin fixtures diverged"); OK();
    /* follower mode: B's roots as A's expectations at height 2 */
    static v2x_env_t e3;
    CHECK(env_utxo(&e3, 0x03, 9) == 0, "e3");
    nodus_v2_envelope_t v3 = { e3.bytes, e3.len };
    nodus_v2_block_t b2a, b2b;
    mk_block(&b2a, 2, &v3, 1);
    CHECK(nodus_witness_v2_apply_block(fa.w, &b2a) == 0, "A2");
    mk_block(&b2b, 2, &v3, 1);
    b2b.expect_global_root = b2a.out_global_root;
    b2b.expect_tx_root = b2a.out_tx_root;
    CHECK(nodus_witness_v2_apply_block(fb.w, &b2b) == 0,
          "follower expectations rejected an identical block"); OK();
    /* restart reproduces committed roots byte-identically */
    uint8_t g0[64], g1[64];
    CHECK(nodus_witness_global_root_v2(fa.w, g0, NULL, NULL, NULL) == 0,
          "g0");
    CHECK(fx_reopen(&fa) == 0, "reopen");
    CHECK(nodus_witness_global_root_v2(fa.w, g1, NULL, NULL, NULL) == 0 &&
          memcmp(g0, g1, 64) == 0, "restart roots diverged"); OK();
    /* replay after restart is idempotent — O14 D6: the no-write path is
     * follower mode, so assert the id the engine derived pre-restart. */
    uint8_t id2[64];
    CHECK(v2x_block_id_at(fa.w, 2, id2) == 0, "read committed id2");
    nodus_v2_block_t br;
    mk_block(&br, 2, &v3, 1);
    br.expect_block_id = id2;
    CHECK(nodus_witness_v2_apply_block(fa.w, &br) == 1, "replay"); OK();
    fx_close(&fa);
    fx_close(&fb);
    return 0;
}

int main(void) {
    /* O15J Faz 2 — this file runs with emission ON, deliberately.
     *
     * An earlier version set `v2x_inflation_off = 1` here on the claim
     * that "emission adds work to every block". Review R2-F8 refuted it:
     * emission consumes ZERO metered units. The real breakage was an
     * unordered, unfiltered read of v2_domain_updates inside the test
     * (now fixed at its site), and quieting the file would have deleted
     * metering coverage on the configuration production actually runs. */

    if (test_epoch()) return 1;
    if (test_local_index()) return 1;
    if (test_resolution()) return 1;
    if (test_meter_authority()) return 1;
    if (test_reads_and_hostile()) return 1;
    if (test_determinism()) return 1;
    printf("test_v2_exec: ALL %d checks passed\n", g_checks);
    return 0;
}
