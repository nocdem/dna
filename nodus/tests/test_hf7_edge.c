/**
 * @file nodus/tests/test_hf7_edge.c
 * @brief HF-7 P1d — the generation-5 EDGE through the engine: a committed
 *        param-22 (RULESET_GEN_ROOTS = D5) row switches the registry
 *        4 -> 5 at the end of block A-1 (phase 6b''''), seeds every head's
 *        last_upd_hash, and from block A the roots generation judges.
 *
 * Design docs/plans/2026-09-11-nodus-ledger-snapshot-design.md §10.2 items
 * 1-3, §10.3 (the transition matrix), §10.9, §10.11; decision docs/plans/
 * decisions/2026-10-20-kurultay-27-hf7-p1-summary.md items 1, 2, 4, 7. The
 * HF-6 template: test_hf4_switch.c case F (t_storage_switch) — same
 * fixture shape, one edge further.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  A. THE EDGE, production runtimes, EVM-enabled build, an S19 database,
 *     rows committed before genesis: HF-2 on from 1, param 9 at 3, param
 *     14 (EVM_ACTIVE) at 5, param 18 (D4) at 8, param 22 (D5) at A = 11;
 *     idle blocks 1..9:
 *   A1. before the edge (end of block 9): the registry is generation 4
 *       (SYSTEM v10 / CORE v9), every head's last_upd_hash is NULL;
 *   A2. block A-1 = 10 commits and AT ITS END (the ORCHESTRATOR's (a),
 *       (b), (c)):
 *       (c) the registry is generation 5 — SYSTEM v11 / CORE v10 with the
 *           compiled generation-5 hashes, both runtimes resolve generation
 *           5, the EVM record still the EVM generation's v2;
 *       (b) SYSTEM and CORE are touched — one DomainUpdate each at A-1,
 *           naming SYSTEM v11 / CORE v10, SYSTEM's root moved;
 *       (a) every head carries a last_upd_hash and it equals today's
 *           history answer (the latest DomainUpdate's hash — for SYSTEM /
 *           CORE the A-1 update phase 10 wrote, for the EVM domain the
 *           seeded value) and nodus_witness_v2_head_last_upd agrees with
 *           its mirror;
 *       the committed SYSTEM root is the v6 composition
 *       (nodus_witness_system_root_v6) and no longer v5; v2_replay is
 *       EMPTY; the committed global root == dna_v2_global_root_v2(the
 *       domains root, the S7 EMPTY replay root) == the recomputation, and
 *       != the GLOBAL v1 formula.
 *   A3. block A (= 11): a SYSTEM CHAIN_CONFIG envelope with expiry 0 (out
 *       of the D2 window) is a node FAULT naming phase 0d, the database
 *       byte-identical; the same leg with expiry A + 5 APPLIES and leaves
 *       exactly one v2_replay row, expiry A + 5; the registry stays at 5.
 *   A4. block A + 1: the SAME envelope bytes again are refused REPLAY (the
 *       v2_replay guard); its row is still the only one.
 *  B. the edge with the registry still at the EVM generation (param 22 at
 *     7, no param-18 row): block 6 is a node FAULT ("registry is not
 *     generation 4"), the database byte-unchanged — the state the vote's
 *     rule (c) keeps out of reach of transactions.
 *  C. a param-22 row whose value is not this build's D5 (inserted by hand
 *     — the scalar rules admit nothing else): the edge block is a node
 *     FAULT naming the generation-5 vote D5.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: NODUS_EVM_ENABLED (generations 3-5 exist only there; the
 * target is registered only in that configuration); DNAC_EPOCH_LENGTH > 13
 * (checked — no epoch boundary among the heights used; the default 720
 * qualifies). Environment: none. The seeded database is climbed to S19
 * (nodus_witness_db_migrate_v2s19) before the genesis.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * One /tmp/test_hf7_edge_<tag>_XXXXXX directory per case, removed at its
 * end (left behind when a CHECK aborts).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - The param-22 / -18 / -14 / -9 rows are written by hand BEFORE the
 *    genesis, so no vote is cast: the vote rules are test_hf7_activation.c
 *    section 4's, not exercised here.
 *  - A3 / A4 fabricate the committee quorum inside a probe SYSTEM exec
 *    (the test_hf4_switch D/E pattern: the fixture's validators have no
 *    secret keys); the auth hook still verifies the real submitter
 *    signature. The probe table is a copy of the compiled table with ONLY
 *    the generation-5 SYSTEM exec replaced, installed AFTER block A-1 —
 *    so A1/A2 run the unmodified production table.
 *  - A2 pins the roots by SELF-CONSISTENCY (committed == recomputed, v6 ≠
 *    v5, GLOBAL v2 ≠ v1), not by an oracle literal: the fixture's whole
 *    state is not oracle-computable. The S4-S8 composition bytes are
 *    pinned against the oracle KAT in test_roots_hf7.
 *  - The same-block coincidence of the generation-4 and generation-5
 *    edges is NOT exercised (rule (c) makes it unreachable; with 6b''''
 *    after 6b''' it would chain 3 -> 4 -> 5 rather than FAULT — stated
 *    in nodus_witness_v2_apply.c phase_6b_gen5_edge).
 *  - A schema other than S19 at the edge is not induced (no downgrade
 *    path exists); the S19 check is read in the source only.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_runtime.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/dnac.h"
#include "dnac/domain_wire.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/ledger_roots_v2.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#include "v2_genesis_fixture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <unistd.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
    g_checks++; \
} while (0)

static int g_checks = 0;

#define E_LEN   ((uint64_t)DNAC_EPOCH_LENGTH)
#define GRACE_E ((uint64_t)DNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS)
#define MAXH    16

/* the heights of case A */
#define H9   3u     /* param 9: generation 2 from block 3                  */
#define HE   5u     /* param 14: the EVM generation from block 5           */
#define HS   8u     /* param 18: generation 4 from block 8                 */
#define HA   11u    /* param 22: generation 5 from block A = 11            */

/* ══ fixture ══════════════════════════════════════════════════════════ */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain16[16];
} fixture_t;

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    fx->w->v2_runtime_table = NULL;
    fx->w->v2_runtime_table_n = 0;
    if (fx->w->db) sqlite3_close(fx->w->db);
    free(fx->w);
    fx->w = NULL;
    char cmd[200];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", fx->dir);
    if (system(cmd) != 0) { /* best effort */ }
}

static int cc_row(nodus_witness_t *w, unsigned param, uint64_t value,
                  uint64_t effective, uint64_t nonce) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO chain_config_history (param_id, new_value, "
            "effective_block, commit_block, tx_hash, proposal_nonce, "
            "created_at_unix) VALUES (?1, ?2, ?3, 0, zeroblob(64), ?4, 0)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)param);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)value);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)effective);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)nonce);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    w->chain_config_cache_warm = false;
    return rc == SQLITE_DONE ? 0 : -1;
}

/* HF-2 on from 1; param 9 at `h9`, param 14 at `he`, param 18 at `hs`,
 * param 22 (value `v22`) at `ha` — each 0 = no row — all before the engine
 * genesis, on an S19 database (test_hf4_switch fx_open_storage's shape). */
static int fx_open(fixture_t *fx, const char *tag, uint64_t h9, uint64_t he,
                   uint64_t hs, uint64_t ha, uint64_t v22) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));      /* multi-MB — ALWAYS heap */
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_hf7_edge_%s_XXXXXX", tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain16, 0x57, sizeof(fx->chain16));
    if (v2x_seed_prepare(fx->w, fx->chain16, 0) != 0) return -1;
    {
        uint32_t ver = 0;
        if (nodus_witness_db_migrate_v2s19(fx->w) != 0 ||
            nodus_witness_db_schema_version(fx->w, &ver) != 0 ||
            ver != NODUS_V2_SCHEMA_VERSION_S19)
            return -1;
    }
    if (cc_row(fx->w, DNAC_CFG_HF2_ACTIVE, DNAC_CFG_HF2_ACTIVE_ON, 1, 11)
        != 0)
        return -1;
    if (h9 && cc_row(fx->w, DNAC_CFG_RULESET_GEN2,
                     (uint64_t)DNAC_CFG_RULESET_GEN2_D2, h9, 12) != 0)
        return -1;
    if (he && cc_row(fx->w, DNAC_CFG_EVM_ACTIVE,
                     (uint64_t)DNAC_CFG_EVM_ACTIVE_D, he, 14) != 0)
        return -1;
    if (hs && cc_row(fx->w, DNAC_CFG_RULESET_GEN_ROLES,
                     (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D, hs, 13) != 0)
        return -1;
    if (ha && cc_row(fx->w, DNAC_CFG_RULESET_GEN_ROOTS, v22, ha, 15) != 0)
        return -1;
    return v2x_seed_genesis(fx->w, fx->chain16, 0, NULL, 0, NULL);
}

static void mk_block(nodus_v2_block_t *b, uint64_t h,
                     const nodus_v2_envelope_t *envs, size_t n) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = nodus_v2_epoch_for_height(h);
    b->envs = envs;
    b->n_envs = n;
}

static int run_idle(fixture_t *fx, uint64_t first, uint64_t last) {
    nodus_v2_block_t b;
    for (uint64_t h = first; h <= last; h++) {
        mk_block(&b, h, NULL, 0);
        if (v2x_cmt_apply_ok(fx->w, &b) != 0) return -1;
    }
    return 0;
}

static int count_q(nodus_witness_t *w, const char *sql, sqlite3_int64 *n) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) *n = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return rc == SQLITE_ROW ? 0 : -1;
}

/* the registry manifest of one domain */
static int reg_man(nodus_witness_t *w, uint32_t dom,
                   dna_domain_manifest_t *m) {
    return nodus_witness_domreg_get(w, dom, NULL, m, NULL);
}

/* every head's domain id + last_upd_hash state, domain_id ASC:
 * st[i] 0 NULL, 1 a 64-byte BLOB, 2 anything else. @return count / -1. */
static int heads_luh(nodus_witness_t *w, uint32_t *ids, uint8_t (*luh)[64],
                     int *st) {
    sqlite3_stmt *q = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT domain_id, last_upd_hash, typeof(last_upd_hash) FROM "
            "v2_domain_heads ORDER BY domain_id ASC", -1, &q, NULL)
        != SQLITE_OK)
        return -1;
    int n = 0, bad = 0;
    while (sqlite3_step(q) == SQLITE_ROW) {
        if (n >= MAXH) { bad = 1; break; }
        ids[n] = (uint32_t)sqlite3_column_int64(q, 0);
        const char *t = (const char *)sqlite3_column_text(q, 2);
        memset(luh[n], 0, 64);
        if (t && strcmp(t, "null") == 0) {
            st[n] = 0;
        } else if (t && strcmp(t, "blob") == 0 &&
                   sqlite3_column_bytes(q, 1) == 64) {
            memcpy(luh[n], sqlite3_column_blob(q, 1), 64);
            st[n] = 1;
        } else {
            st[n] = 2;
        }
        n++;
    }
    sqlite3_finalize(q);
    return bad ? -1 : n;
}

/* today's history answer: the latest update hash of `d`, the genesis
 * sentinel when it never had one. 0 / -1. */
static int latest_upd(nodus_witness_t *w, uint32_t d, uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "SELECT upd_hash FROM v2_domain_updates "
                           "WHERE domain_id = ?1 ORDER BY global_height "
                           "DESC LIMIT 1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)d);
    int rc = sqlite3_step(st);
    int ret = -1;
    if (rc == SQLITE_ROW && sqlite3_column_bytes(st, 0) == 64) {
        memcpy(out, sqlite3_column_blob(st, 0), 64);
        ret = 0;
    } else if (rc == SQLITE_DONE) {
        ret = dna_dupd_prev_genesis(out) == 0 ? 0 : -1;
    }
    sqlite3_finalize(st);
    return ret;
}

static int upd_at(nodus_witness_t *w, uint64_t gh, uint32_t dom,
                  dna_domain_update_t *u) {
    sqlite3_stmt *st = NULL;
    int ok = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT upd FROM v2_domain_updates WHERE "
                           "global_height = ?1 AND domain_id = ?2", -1, &st,
                           NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)gh);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)dom);
    if (sqlite3_step(st) == SQLITE_ROW &&
        dna_dupd_decode(sqlite3_column_blob(st, 0),
                        (size_t)sqlite3_column_bytes(st, 0), u) == 0)
        ok = 0;
    sqlite3_finalize(st);
    return ok;
}

/* the COMMITTED domain state root of `dom` (head bytes 4..67) */
static int head_root(nodus_witness_t *w, uint32_t dom, uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    int ok = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT head FROM v2_domain_heads WHERE "
                           "domain_id = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)dom);
    if (sqlite3_step(st) == SQLITE_ROW &&
        sqlite3_column_bytes(st, 0) == DNA_V2_DOMHEAD_ENC_LEN) {
        memcpy(out, (const uint8_t *)sqlite3_column_blob(st, 0) + 4, 64);
        ok = 0;
    }
    sqlite3_finalize(st);
    return ok;
}

/* the committed global root of block `h` */
static int block_global(nodus_witness_t *w, uint64_t h, uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "SELECT global_root FROM v2_blocks WHERE "
                           "global_height = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)h);
    int ok = sqlite3_step(st) == SQLITE_ROW &&
             sqlite3_column_bytes(st, 0) == 64;
    if (ok) memcpy(out, sqlite3_column_blob(st, 0), 64);
    sqlite3_finalize(st);
    return ok ? 0 : -1;
}

/* ══ the probe SYSTEM exec (test_hf4_switch D/E): a quorum verdict ═════ */

static int probe_exec(const nodus_domain_runtime_t *rt,
                      const dna_env_view_t *env, uint16_t leg_index,
                      const nodus_rt_exec_ctx_t *ctx,
                      const nodus_rt_read_res_t *reads, uint16_t n_reads,
                      uint8_t *res_out, size_t res_cap, size_t *res_len_out) {
    if (!ctx || !ctx->auth) return -2;
    nodus_rt_auth_verdict_t av = *ctx->auth;
    av.n_approvals = 7;
    av.committee_n = 7;
    av.approved_power = 7;
    av.committee_power = 7;
    nodus_rt_exec_ctx_t c2 = *ctx;
    c2.auth = &av;
    return nodus_rt_system_exec(rt, env, leg_index, &c2, reads, n_reads,
                                res_out, res_cap, res_len_out);
}

static nodus_domain_runtime_t *g_probe = NULL;

/* the compiled table, copied, with ONLY the generation-5 SYSTEM exec
 * replaced; every tuple unchanged, so the committed registry resolves
 * onto the same entries */
static int probe_install(nodus_witness_t *w) {
    size_t n = 0;
    const nodus_domain_runtime_t *all = nodus_runtime_all_table(&n);
    if (!all || n == 0) return -1;
    free(g_probe);
    g_probe = malloc(n * sizeof(*g_probe));
    if (!g_probe) return -1;
    memcpy(g_probe, all, n * sizeof(*g_probe));
    int hit = 0;
    for (size_t i = 0; i < n; i++)
        if (g_probe[i].generation == NODUS_RT_GEN_ROOTS &&
            g_probe[i].domain_id == DNA_DOMAIN_SYSTEM) {
            g_probe[i].exec = probe_exec;
            hit++;
        }
    if (hit != 1) return -1;
    w->v2_runtime_table = g_probe;
    w->v2_runtime_table_n = n;
    return 0;
}

#define CC_CALL_LEN 41u
#define K1_AUTH_LEN (1u + NODUS_RT_AUTH_SIGNER_LEN)

typedef struct {
    uint8_t  call[CC_CALL_LEN];
    uint8_t  auth[K1_AUTH_LEN];
    uint8_t *bytes;
    size_t   len;
} cc_env_t;

static uint8_t g_pk[QGP_DSA87_PUBLICKEYBYTES], g_sk[QGP_DSA87_SECRETKEYBYTES];

static void put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}

/* One SYSTEM CHAIN_CONFIG envelope (test_hf4_switch cc_env_build) with
 * expiry `expiry`, auth_kind 1, REALLY signed by g_sk over the engine-
 * derived leg digest at candidate `height`. @return 0 / -1. */
static int cc_env_build(nodus_witness_t *w, uint64_t height, uint8_t param,
                        uint64_t value, uint64_t effective, uint64_t nonce,
                        uint64_t expiry, cc_env_t *e) {
    dna_domain_manifest_t sys;
    memset(e, 0, sizeof(*e));
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_SYSTEM, NULL, &sys, NULL) != 0)
        return -1;
    e->call[0] = param;
    put64(e->call + 1, value);
    put64(e->call + 9, effective);
    put64(e->call + 17, nonce);
    put64(e->call + 25, height);                /* signed_at              */
    put64(e->call + 33, effective + 1000u);     /* valid_before           */

    dna_env_leg_in_t leg;
    memset(&leg, 0, sizeof(leg));
    leg.hdr.domain_id            = DNA_DOMAIN_SYSTEM;
    leg.hdr.runtime_op           = DNA_SYSRULE_CHAIN_CONFIG;
    leg.hdr.ruleset_version      = sys.ruleset_version;
    leg.hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
    leg.hdr.auth_kind            = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    leg.hdr.call_len             = CC_CALL_LEN;
    leg.hdr.auth_len             = K1_AUTH_LEN;
    leg.hdr.res_max_effects      = 4;
    leg.hdr.res_max_effect_bytes = 4096;
    leg.call_data = e->call;
    leg.auth_data = e->auth;

    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.expiry_height       = expiry;
    in.fee_amount          = 0;
    in.res_max_total_units = 200000;
    in.leg_count           = 1;
    in.legs                = &leg;

    dna_env_leg_ctx_t lctx;
    memset(&lctx, 0, sizeof(lctx));
    lctx.domain_id       = DNA_DOMAIN_SYSTEM;
    lctx.ruleset_version = sys.ruleset_version;
    memcpy(lctx.ruleset_hash, sys.ruleset_hash, 64);

    if (dna_env_encoded_size(&leg, 1, &e->len) != 0) return -1;
    e->bytes = malloc(e->len);
    if (!e->bytes) return -1;
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    if (!pf) return -1;
    size_t used = 0;
    int ok = -1;
    do {
        if (dna_env_encode(&in, e->bytes, e->len, &used) != 0 ||
            used != e->len) break;
        if (dna_env_preflight(e->bytes, e->len, w->v2_chain32, height,
                              &lctx, 1, pf) != DNA_ENV_PF_OK) break;
        e->auth[0] = 1;
        memcpy(e->auth + 1, g_pk, QGP_DSA87_PUBLICKEYBYTES);
        size_t sl = 0;
        if (qgp_dsa87_sign(e->auth + 1 + QGP_DSA87_PUBLICKEYBYTES, &sl,
                           pf->auth_digest[0], 64, g_sk) != 0) break;
        if (dna_env_encode(&in, e->bytes, e->len, &used) != 0 ||
            used != e->len) break;
        ok = 0;
    } while (0);
    free(pf);
    return ok;
}

/* ══ A. the generation-5 edge at A-1, block A, block A+1 ═════════════ */

static int t_edge(void) {
    fixture_t fx;
    nodus_v2_block_t b;
    const nodus_domain_runtime_t *s4 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *c4 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_CORE);
    const nodus_domain_runtime_t *s5 =
        nodus_runtime_for_generation(NODUS_RT_GEN_ROOTS, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *c5 =
        nodus_runtime_for_generation(NODUS_RT_GEN_ROOTS, DNA_DOMAIN_CORE);
    const nodus_domain_runtime_t *ev =
        nodus_runtime_for_generation(NODUS_RT_GEN_EVM, DNA_DOMAIN_EVM);
    CHECK(s4 && c4 && s5 && c5 && ev, "compiled generations 3-5");
    CHECK(E_LEN > HA + 2u, "no epoch boundary among heights 1..A+1");

    CHECK(fx_open(&fx, "edge", H9, HE, HS, HA,
                  (uint64_t)DNAC_CFG_RULESET_GEN_ROOTS_D) == 0,
          "seeded S19 chain (HF-2 on, params 9 / 14 / 18 / 22 at "
          "3 / 5 / 8 / 11)");

    /* ── A1. blocks 1..A-2: generation 4 from the end of block HS-1 ── */
    CHECK(run_idle(&fx, 1, HA - 2u) == 0, "idle blocks 1..A-2");
    {
        dna_domain_manifest_t ms, mc;
        CHECK(reg_man(fx.w, DNA_DOMAIN_SYSTEM, &ms) == 0 &&
              reg_man(fx.w, DNA_DOMAIN_CORE, &mc) == 0, "registry");
        CHECK(ms.ruleset_version == 10 && mc.ruleset_version == 9,
              "before the edge: generation 4 (SYSTEM v10 / CORE v9)");
        uint32_t ids[MAXH];
        uint8_t luh[MAXH][64];
        int st[MAXH];
        int n = heads_luh(fx.w, ids, luh, st);
        CHECK(n >= 3, "SYSTEM, CORE and EVM heads");
        for (int i = 0; i < n; i++)
            CHECK(st[i] == 0, "before the edge every last_upd_hash is NULL");
        sqlite3_int64 nr = -1;
        CHECK(count_q(fx.w, "SELECT COUNT(*) FROM v2_replay", &nr) == 0 &&
              nr == 0, "v2_replay empty before the edge");
    }
    uint8_t sys_before[64];
    CHECK(head_root(fx.w, DNA_DOMAIN_SYSTEM, sys_before) == 0,
          "SYSTEM root at A-2");

    /* ── A2. block A-1: THE GENERATION-5 EDGE ── */
    mk_block(&b, HA - 1u, NULL, 0);
    CHECK(v2x_cmt_apply_ok(fx.w, &b) == 0, "the A-1 block commits");
    {
        /* (c) the registry switched 4 -> 5, the EVM record untouched */
        dna_domain_manifest_t ms, mc, me;
        CHECK(reg_man(fx.w, DNA_DOMAIN_SYSTEM, &ms) == 0 &&
              reg_man(fx.w, DNA_DOMAIN_CORE, &mc) == 0 &&
              reg_man(fx.w, DNA_DOMAIN_EVM, &me) == 0, "registry after");
        CHECK(ms.ruleset_version == 11 && mc.ruleset_version == 10,
              "(c) SYSTEM v11 / CORE v10 at the end of A-1");
        CHECK(memcmp(ms.ruleset_hash, s5->ruleset_hash, 64) == 0 &&
              memcmp(mc.ruleset_hash, c5->ruleset_hash, 64) == 0,
              "(c) the compiled generation-5 hashes");
        CHECK(me.ruleset_version == ev->ruleset_version &&
              memcmp(me.ruleset_hash, ev->ruleset_hash, 64) == 0,
              "the EVM record is still the EVM generation's v2");
        const nodus_domain_runtime_t *rs = NULL, *rc = NULL;
        CHECK(nodus_witness_v2_runtime_for(fx.w, DNA_DOMAIN_SYSTEM, 1, &rs)
                  == 0 && rs == s5, "SYSTEM resolves generation 5");
        CHECK(nodus_witness_v2_runtime_for(fx.w, DNA_DOMAIN_CORE, 1, &rc)
                  == 0 && rc == c5, "CORE resolves generation 5");
    }
    {
        /* (b) SYSTEM and CORE touched at A-1 */
        dna_domain_update_t us, uc;
        CHECK(upd_at(fx.w, HA - 1u, DNA_DOMAIN_SYSTEM, &us) == 0 &&
              upd_at(fx.w, HA - 1u, DNA_DOMAIN_CORE, &uc) == 0,
              "(b) a DomainUpdate for SYSTEM and CORE at A-1");
        CHECK(us.ruleset_version == 11 && uc.ruleset_version == 10,
              "(b) the A-1 updates name generation 5");
        CHECK(memcmp(us.pre_root, sys_before, 64) == 0 &&
              memcmp(us.pre_root, us.post_root, 64) != 0,
              "(b) SYSTEM's root moved from the A-2 value");
        CHECK(us.res_tx_count == 0 && uc.res_tx_count == 0,
              "no item carried them");
    }
    {
        /* (a) every head seeded; the column is today's history answer */
        uint32_t ids[MAXH];
        uint8_t luh[MAXH][64];
        int st[MAXH];
        int n = heads_luh(fx.w, ids, luh, st);
        CHECK(n >= 3, "heads after the edge");
        int saw_evm = 0;
        for (int i = 0; i < n; i++) {
            uint8_t want[64], via[64];
            CHECK(st[i] == 1, "(a) every head carries a 64-byte "
                  "last_upd_hash at the end of A-1");
            CHECK(latest_upd(fx.w, ids[i], want) == 0 &&
                  memcmp(luh[i], want, 64) == 0,
                  "(a) the column == the latest update hash");
            CHECK(nodus_witness_v2_head_last_upd(fx.w, ids[i], via) ==
                      NODUS_V2_LUH_OK && memcmp(via, want, 64) == 0,
                  "(a) the head-authoritative read agrees with its mirror");
            if (ids[i] == DNA_DOMAIN_EVM) saw_evm = 1;
        }
        CHECK(saw_evm, "the EVM domain's untouched head was seeded too");
    }
    {
        /* SYSTEM v6, v2_replay empty, GLOBAL v2 over the EMPTY replay root */
        uint8_t committed[64], v6[64], v5[64];
        CHECK(head_root(fx.w, DNA_DOMAIN_SYSTEM, committed) == 0 &&
              nodus_witness_system_root_v6(fx.w, v6) == 0 &&
              nodus_witness_system_root_v5(fx.w, v5) == 0, "v6 / v5");
        CHECK(memcmp(committed, v6, 64) == 0,
              "at A-1 the committed SYSTEM root is NDS.SYS.v6");
        CHECK(memcmp(committed, v5, 64) != 0, "and no longer v5");
        sqlite3_int64 nr = -1;
        CHECK(count_q(fx.w, "SELECT COUNT(*) FROM v2_replay", &nr) == 0 &&
              nr == 0, "no v2_replay row at A-1 (matrix §10.3)");
        uint8_t g_commit[64], g_fresh[64], doms[64], empty[64], g2[64],
                g1[64], rr[64];
        CHECK(block_global(fx.w, HA - 1u, g_commit) == 0,
              "the committed A-1 global root");
        CHECK(nodus_witness_global_root_v2(fx.w, g_fresh, doms, NULL, NULL)
                  == 0, "recomputed global root");
        CHECK(memcmp(g_commit, g_fresh, 64) == 0,
              "committed A-1 global root == recomputation");
        CHECK(dna_v2_empty_root(DNA_V2_EMPTY_REPLAY, empty) == 0 &&
              nodus_witness_replay_root(fx.w, rr) == 0 &&
              memcmp(rr, empty, 64) == 0,
              "the replay leg is the S7 EMPTY root");
        CHECK(dna_v2_global_root_v2(doms, empty, g2) == 0 &&
              memcmp(g_commit, g2, 64) == 0,
              "GLOBAL v2 = H(domains_root v2 ‖ the empty replay root)");
        CHECK(dna_v2_global_root(doms, g1) == 0 &&
              memcmp(g_commit, g1, 64) != 0, "not the GLOBAL v1 formula");
    }

    /* ── A3. block A under generation 5 ── */
    CHECK(probe_install(fx.w) == 0, "probe runtime table (gen-5 SYSTEM)");
    {
        uint8_t d0[64], d1[64];
        cc_env_t bad;
        const uint64_t eff = HA + GRACE_E;
        CHECK(cc_env_build(fx.w, HA, (uint8_t)DNAC_CFG_GAS_PRICE_RAW_PER_UNIT,
                           0, eff, 21, 0, &bad) == 0,
              "a CHAIN_CONFIG envelope with expiry 0");
        nodus_v2_envelope_t e1[1] = { { bad.bytes, bad.len } };
        CHECK(v2x_db_digest(fx.w, d0) == 0, "digest before");
        mk_block(&b, HA, e1, 1);
        CHECK(v2x_cmt_fault_why(fx.w, &b, V2X_FAULT, "phase 0d") == 0,
              "D2 at A: an expiry-0 item makes the block a node FAULT "
              "(phase 0d), never a failed item");
        CHECK(v2x_db_digest(fx.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
              "the database is byte-identical");
        free(bad.bytes);
    }
    cc_env_t good;
    {
        const uint64_t eff = HA + GRACE_E;
        CHECK(cc_env_build(fx.w, HA, (uint8_t)DNAC_CFG_GAS_PRICE_RAW_PER_UNIT,
                           0, eff, 22, HA + 5u, &good) == 0,
              "the same leg with expiry A + 5");
        nodus_v2_envelope_t e1[1] = { { good.bytes, good.len } };
        mk_block(&b, HA, e1, 1);
        CHECK(v2x_cmt_apply_ok(fx.w, &b) == 0,
              "block A applies the in-window envelope");
        sqlite3_int64 nr = -1, ne = -1;
        CHECK(count_q(fx.w, "SELECT COUNT(*) FROM v2_replay", &nr) == 0 &&
              nr == 1, "exactly one v2_replay row after A");
        char q[160];
        snprintf(q, sizeof(q), "SELECT COUNT(*) FROM v2_replay WHERE "
                 "expiry_height = %llu", (unsigned long long)(HA + 5u));
        CHECK(count_q(fx.w, q, &ne) == 0 && ne == 1,
              "its expiry_height is A + 5");
        dna_domain_manifest_t ms;
        CHECK(reg_man(fx.w, DNA_DOMAIN_SYSTEM, &ms) == 0 &&
              ms.ruleset_version == 11, "no second switch at A");
    }

    /* ── A4. block A+1: the same bytes again → REPLAY ── */
    {
        nodus_v2_envelope_t e1[1] = { { good.bytes, good.len } };
        mk_block(&b, HA + 1u, e1, 1);
        CHECK(v2x_cmt_apply(fx.w, &b) == 0, "block A+1 commits");
        CHECK(b.cmt.results[0].code == NODUS_V2_TX_ERR_REPLAY,
              "the resubmitted envelope is refused REPLAY by v2_replay");
        sqlite3_int64 nr = -1;
        CHECK(count_q(fx.w, "SELECT COUNT(*) FROM v2_replay", &nr) == 0 &&
              nr == 1, "still exactly one v2_replay row");
    }
    free(good.bytes);
    fx_close(&fx);
    return 0;
}

/* ══ B. the edge on a registry that is not generation 4 → FAULT ══════ */

static int t_edge_not_gen4_faults(void) {
    fixture_t fx;
    nodus_v2_block_t b;
    /* param 9 at 3, param 14 at 5, NO param 18, param 22 at 7 */
    CHECK(fx_open(&fx, "notg4", H9, HE, 0, 7,
                  (uint64_t)DNAC_CFG_RULESET_GEN_ROOTS_D) == 0,
          "seeded chain (param 22 at 7, registry at the EVM generation)");
    CHECK(run_idle(&fx, 1, 5) == 0, "idle blocks 1..5");
    mk_block(&b, 6, NULL, 0);
    CHECK(v2x_cmt_fault_why(fx.w, &b, V2X_FAULT,
                            "registry is not generation 4") == 0,
          "the generation-5 edge on a generation-3 registry is a node "
          "FAULT, DB byte-unchanged");
    fx_close(&fx);
    return 0;
}

/* ══ C. a param-22 row that is not this build's D5 → FAULT ═══════════ */

static int t_edge_wrong_value_faults(void) {
    fixture_t fx;
    nodus_v2_block_t b;
    CHECK(fx_open(&fx, "wrongd", H9, HE, HS, HA,
                  (uint64_t)DNAC_CFG_RULESET_GEN_ROOTS_D + 1u) == 0,
          "seeded chain (param 22 at 11 with D5 + 1)");
    CHECK(run_idle(&fx, 1, HA - 2u) == 0, "idle blocks 1..A-2");
    mk_block(&b, HA - 1u, NULL, 0);
    CHECK(v2x_cmt_fault_why(fx.w, &b, V2X_FAULT,
                            "generation-5 vote D5") == 0,
          "a param-22 row holding another value is a node FAULT at A-1");
    fx_close(&fx);
    return 0;
}

int main(void) {
    static const struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        { "gen5_edge_a_minus_1_and_a", t_edge },
        { "gen5_edge_not_gen4_faults", t_edge_not_gen4_faults },
        { "gen5_edge_wrong_value",     t_edge_wrong_value_faults },
    };
    size_t failed = 0, n = sizeof(cases) / sizeof(cases[0]);
    {
        uint8_t seed[32];
        memset(seed, 0x5E, sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_pk, g_sk, seed) != 0) {
            fprintf(stderr, "test_hf7_edge: key generation failed\n");
            return 1;
        }
    }
    for (size_t i = 0; i < n; i++) {
        int rc = cases[i].fn();
        fprintf(stderr, "%-28s %s\n", cases[i].name, rc == 0 ? "ok" : "FAIL");
        if (rc != 0) failed++;
    }
    free(g_probe);
    fprintf(stderr, "test_hf7_edge: %zu/%zu cases passed, %d checks\n",
            n - failed, n, g_checks);
    return failed ? 1 : 0;
}
