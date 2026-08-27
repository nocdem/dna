/**
 * Nodus — Ledger V2: atomic apply engine on the TYPED EXECUTION PATH
 * (execution season), genesis roots, supply gate, rollback and
 * cross-domain atomicity (INACTIVE layer).
 *
 * The raw-SQL op scaffold is gone: every block below carries ENVELOPES,
 * whose state transitions run through preflight → derived identity →
 * frozen-snapshot runtime resolution → reservation → native scripted
 * exec → typed-effect decode/validate/charge → adapter application
 * (fixture: v2_exec_fixture.h — builtin-copied SYSTEM/CORE runtimes
 * with compiled test adapters over the same tables the old SQL ops
 * mutated).
 *
 * Rollback claims are NEVER made from return codes alone: db_state_digest
 * serializes EVERY table (sorted names, rows by rowid, typed column
 * bytes) into one SHA3-512 and the tests byte-compare it around every
 * fault point.
 *
 * Sections:
 *   1. Genesis: migrate + v2_genesis; idempotent / conflicting re-run;
 *      DERIVED-EPOCH gate (nonzero genesis epoch rejects); GENESIS-ROOT
 *      CYCLE PROOF (unchanged from S5/S7).
 *   2. Heads/updates: initial heads; CORE-only block (SYSTEM does not
 *      advance); SYSTEM-only block; two-tx one-update with DERIVED-id
 *      local indices; declared-no-op rejects (empty typed result);
 *      undeclared mutation (adapter domain-escape) rejects; wrong
 *      expected root; wrong block epoch rejects.
 *   3. Replay: idempotent re-apply (rc 1, digest unchanged), same-height
 *      conflict, height gap, wrong prev, reused BlockID.
 *   4. Cross-domain atomicity: one envelope with SYSTEM+CORE legs →
 *      both commit (one DERIVED identity, two local indices); faults →
 *      NEITHER commits.
 *   5. Fault injection F1..F14 + F26 (post-reserve) + F27 (post-env-
 *      exec) on a rich block: rc −1 and the FULL DB digest is
 *      byte-identical; F15: rc 2, committed, restart reconstructs.
 *   6. Resource limits: global tx cap; global UNIT budget (reservation
 *      ceiling); per-domain tx quota and per-domain unit budget from a
 *      consistent fixture-written CORE manifest.
 *   7. Supply (fixture 2, official DNA numbers): unchanged direct-SQL
 *      invariant matrix + engine blocks (inflate/mint/settle/burn/
 *      sneak/fault-loop) now driven through typed effects.
 *
 * @file test_v2_apply.c
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

/* ── fs + fixture ───────────────────────────────────────────────────── */
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
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_apply_XXXXXX");
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain_id16, 0x33, sizeof(fx->chain_id16));
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
    fx->w->v2_runtime_table = tbl;      /* the scripted table survives a
                                         * restart like compiled code    */
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

/* ── full-DB digest (the rollback oracle) ───────────────────────────── */
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

/* ── block + envelope helpers ───────────────────────────────────────── */
static void mk_id(uint8_t out[64], uint8_t fill) { memset(out, fill, 64); }

/* O14 LEADER/DERIVATION MODE: a block carries NO identity. The engine
 * derives prev_block_id from the committed parent, validator_set_hash
 * from the block-start authority snapshot, and the BlockID from the
 * canonical header it builds out of its own execution results. A test
 * that wants to ASSERT one of those sets the matching expect_* pointer;
 * fabricating an id is no longer expressible. */
static void mk_block(nodus_v2_block_t *b, uint64_t h,
                     const nodus_v2_envelope_t *envs, size_t n) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = nodus_v2_epoch_for_height(h);
    b->envs = envs;
    b->n_envs = n;
}

/* One CORE UTXO CREATE envelope: 64-byte key = 63 zeros + last byte. */
static int env_core_utxo_create(v2x_env_t *e, uint8_t keylast,
                                uint64_t amount) {
    uint8_t key[64] = { 0 };
    key[63] = keylast;
    uint8_t val[8];
    v2x_put64(val, amount);
    uint8_t res[512];
    size_t rl = 0;
    if (v2x_eff1(res, sizeof(res), V2X_OP_UTXO, DNA_EFFECT_CREATE,
                 DNA_EFFECT_PRE_ABSENT, key, 64, val, 8, &rl) != 0)
        return -1;
    uint8_t call[600];
    uint32_t cl = v2x_script_build(call, sizeof(call), NULL, 0, res, rl);
    if (!cl) return -1;
    v2x_leg_t leg = { 1, 1, call, cl, 4, 2048 };
    return v2x_env_build(e, &leg, 1);
}

/* One CORE UTXO SET envelope (absolute amount). */
static int env_core_utxo_set(v2x_env_t *e, uint8_t keylast,
                             uint64_t amount) {
    uint8_t key[64] = { 0 };
    key[63] = keylast;
    uint8_t val[8];
    v2x_put64(val, amount);
    uint8_t res[512];
    size_t rl = 0;
    if (v2x_eff1(res, sizeof(res), V2X_OP_UTXO, DNA_EFFECT_SET,
                 DNA_EFFECT_PRE_EXISTS, key, 64, val, 8, &rl) != 0)
        return -1;
    uint8_t call[600];
    uint32_t cl = v2x_script_build(call, sizeof(call), NULL, 0, res, rl);
    if (!cl) return -1;
    v2x_leg_t leg = { 1, 1, call, cl, 4, 2048 };
    return v2x_env_build(e, &leg, 1);
}

/* One SYSTEM chain-config CREATE envelope. */
static int env_sys_cc(v2x_env_t *e, uint64_t effblock, uint64_t value) {
    uint8_t key[12];
    v2x_put32(key, 2);                  /* param_id 2                    */
    v2x_put64(key + 4, effblock);
    uint8_t val[8];
    v2x_put64(val, value);
    uint8_t res[512];
    size_t rl = 0;
    if (v2x_eff1(res, sizeof(res), V2X_OP_CC, DNA_EFFECT_CREATE,
                 DNA_EFFECT_PRE_ABSENT, key, 12, val, 8, &rl) != 0)
        return -1;
    uint8_t call[600];
    uint32_t cl = v2x_script_build(call, sizeof(call), NULL, 0, res, rl);
    if (!cl) return -1;
    v2x_leg_t leg = { 0, 1, call, cl, 4, 2048 };
    return v2x_env_build(e, &leg, 1);
}

/* Cross-domain envelope: SYSTEM cc-insert leg + CORE utxo-create leg. */
static int env_cross_cc_utxo(v2x_env_t *e, uint64_t effblock,
                             uint8_t keylast, uint64_t amount) {
    uint8_t skey[12];
    v2x_put32(skey, 2);
    v2x_put64(skey + 4, effblock);
    uint8_t sval[8];
    v2x_put64(sval, 5);
    uint8_t sres[512];
    size_t srl = 0;
    if (v2x_eff1(sres, sizeof(sres), V2X_OP_CC, DNA_EFFECT_CREATE,
                 DNA_EFFECT_PRE_ABSENT, skey, 12, sval, 8, &srl) != 0)
        return -1;
    uint8_t scall[600];
    uint32_t scl = v2x_script_build(scall, sizeof(scall), NULL, 0,
                                    sres, srl);

    uint8_t ckey[64] = { 0 };
    ckey[63] = keylast;
    uint8_t cval[8];
    v2x_put64(cval, amount);
    uint8_t cres[512];
    size_t crl = 0;
    if (v2x_eff1(cres, sizeof(cres), V2X_OP_UTXO, DNA_EFFECT_CREATE,
                 DNA_EFFECT_PRE_ABSENT, ckey, 64, cval, 8, &crl) != 0)
        return -1;
    uint8_t ccall[600];
    uint32_t ccl = v2x_script_build(ccall, sizeof(ccall), NULL, 0,
                                    cres, crl);
    if (!scl || !ccl) return -1;
    v2x_leg_t legs[2] = {
        { 0, 1, scall, scl, 4, 2048 },
        { 1, 1, ccall, ccl, 4, 2048 }
    };
    return v2x_env_build(e, legs, 2);
}

/* CORE-leg envelope carrying an EMPTY typed result (declared no-op). */
static int env_core_empty(v2x_env_t *e) {
    uint8_t res[64];
    size_t rl = 0;
    if (dna_effect_result_encode(NULL, 0, res, sizeof(res), &rl) != 0)
        return -1;
    uint8_t call[128];
    uint32_t cl = v2x_script_build(call, sizeof(call), NULL, 0, res, rl);
    if (!cl) return -1;
    v2x_leg_t leg = { 1, 1, call, cl, 4, 2048 };
    return v2x_env_build(e, &leg, 1);
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

static int head_height(nodus_witness_t *w, int dom, uint64_t *out) {
    char sql[128];
    snprintf(sql, sizeof(sql),
             "SELECT domain_height FROM v2_domain_heads WHERE domain_id=%d",
             dom);
    *out = q1(w, sql);
    return *out == UINT64_MAX ? -1 : 0;
}

/* ── ROGUE SYSTEM adapter: mutate escapes into CORE's utxo_set ───────
 * (the cross-domain-substitution fixture — the untouched-domain guard
 * must reject the block; amount 0 so the supply equation stays silent
 * and ONLY the guard can be the rejector). */
static nodus_adapter_status_t rogue_sys_mutate(
        const nodus_domain_adapter_t *ad, struct nodus_witness *wns,
        uint32_t dom, const nodus_adapter_op_t *op, uint8_t kind,
        const uint8_t *key, uint16_t key_len,
        const uint8_t *value, uint32_t value_len) {
    nodus_adapter_status_t st = v2x_sys_mutate(ad, wns, dom, op, kind,
                                               key, key_len, value,
                                               value_len);
    if (st != NODUS_ADAPTER_OK) return st;
    nodus_witness_t *w = (nodus_witness_t *)wns;
    if (run_sql(w->db,
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
            "tx_hash, output_index, block_height, created_at, "
            "unlock_block, domain_id) VALUES (zeroblob(63)||x'e0', "
            "'rogue', 0, zeroblob(64), zeroblob(63)||x'aa', 0, 1, 0, 0, "
            "1)") != 0)
        return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    return NODUS_ADAPTER_OK;
}

static const nodus_domain_adapter_t ROGUE_SYS_ADAPTER = {
    .adapter_version = NODUS_DOMAIN_ADAPTER_V1,
    .ops = V2X_SYS_OPS,
    .n_ops = 3,
    .probe = v2x_sys_probe,
    .mutate = rogue_sys_mutate,
    .read = v2x_sys_read
};

static nodus_domain_runtime_t g_rogue_table[2];

static void rogue_table_arm(nodus_witness_t *w) {
    memcpy(g_rogue_table, g_v2x_table, sizeof(g_rogue_table));
    g_rogue_table[0].adapter = &ROGUE_SYS_ADAPTER;
    w->v2_runtime_table = g_rogue_table;
    w->v2_runtime_table_n = 2;
}

static void rogue_table_disarm(nodus_witness_t *w) {
    w->v2_runtime_table = g_v2x_table;
    w->v2_runtime_table_n = 2;
}

int main(void) {
    /* O15J Faz 2 — this file pins TOUCH ISOLATION ("SYSTEM advanced while
     * untouched", untouched-domain guards, per-block head heights). The
     * economics port makes every block mint, and a mint legitimately
     * moves both CORE (supply_tracking) and SYSTEM (epoch_state), so a
     * chain with inflation on can no longer express those properties.
     * Quiet chain here; emission is covered by test_v2_econ. */
    v2x_inflation_off = 1;

    fixture_t fx;
    CHECK(fx_open(&fx) == 0, "fixture"); OK();
    CHECK(nodus_witness_db_migrate_v2s9(fx.w) == 0, "migrate"); OK();
    CHECK(v2x_table_init(fx.w) == 0, "scripted table"); OK();

    /* ── 1. genesis + cycle proof ───────────────────────────────────── */
    /* O14: seed the committed validator authority BEFORE capturing the
     * payload roots — the validator/vset legs are part of the SYSTEM
     * payload root, so seeding after the capture would move the root out
     * from under the cycle proof below. */
    CHECK(v2x_seed_authority(fx.w) == 0, "seed authority"); OK();
    /* O15J Faz 2 — same rule, same reason: chain_config_history is also a
     * SYSTEM payload-root leg, so the inflation-OFF row must be in place
     * BEFORE the capture below or the cycle proof compares a root taken
     * without it against a manifest committed with it. */
    CHECK(v2x_seed_inflation_off(fx.w) == 0, "seed inflation off"); OK();
    uint8_t sys_payload_pre[64], core_pre[64];
    CHECK(nodus_witness_system_payload_root_v2(fx.w, sys_payload_pre) == 0,
          "payload pre"); OK();
    {
        size_t nrt = 0;
        const nodus_domain_runtime_t *rt_tab =
            nodus_runtime_builtin_table(&nrt);
        CHECK(rt_tab && nrt == 2 && rt_tab[1].state_init != NULL,
              "CORE state_init hook missing");
        CHECK(rt_tab[1].state_init(&rt_tab[1],
                                   (struct nodus_witness *)fx.w, 0) == 0,
              "pre-genesis CORE state_init");
    }
    CHECK(nodus_witness_core_root_v2(fx.w, core_pre) == 0, "core pre");

    uint8_t gen_id[64], vset[64];
    mk_id(vset, 0x77);
    /* O14: a genesis with NO manifest bytes has no canonical identity —
     * the genesis preimage takes the manifest as an explicit input — so
     * the no-manifest form now fails closed rather than storing an id
     * the caller chose. */
    CHECK(nodus_witness_v2_genesis(fx.w, NULL, vset, 0) == -1,
          "no-manifest genesis accepted"); OK();
    /* DERIVED-EPOCH gate: a genesis claiming any epoch other than the
     * derivation of height 0 (== 0) is rejected outright. */
    CHECK(nodus_witness_v2_genesis(fx.w, NULL, vset, 1) == -1,
          "nonzero genesis epoch accepted"); OK();
    /* O14 review R1-F2: genesis binds validator_set_hash into the chain
     * identity. If it were a free caller parameter it would be the ONE
     * header field with two authoritative producers — derived from the
     * committed snapshot on the apply path, chosen here. It must EQUAL
     * the committed epoch-0 authority. A foreign set rejects. */
    {
        uint8_t foreign[64];
        memset(foreign, 0x5C, sizeof(foreign));
        CHECK(nodus_witness_v2_genesis_ex(fx.w, NULL, foreign, 0,
                                          (const uint8_t *)"m", 1) == -1,
              "genesis bound a foreign validator_set_hash"); OK();
    }
    CHECK(v2x_genesis_min(fx.w, vset, gen_id, NULL) == 0, "genesis");
    OK();
    /* Idempotent re-run: asserting the DERIVED id succeeds. */
    CHECK(v2x_genesis_min(fx.w, vset, NULL, NULL) == 0,
          "genesis not idempotent"); OK();

    /* ── O15A obligation 3: GENESIS MANIFEST DIVERGENCE ───────────────
     * The idempotency probe used to decide on the BlockID ALONE. In
     * leader mode (NULL assertion) that made the comparison
     * unconditionally true, so re-running genesis with a DIFFERENT
     * manifest returned SUCCESS and the presented bytes were never
     * examined — even though the genesis identity is derived from them.
     * The committed manifest is authoritative and a divergent one must
     * fail closed. */
    {
        static const uint8_t other_manifest[] =
            "this is definitively not the committed genesis manifest";
        CHECK(nodus_witness_v2_genesis_ex(fx.w, NULL, vset, 0,
                                          other_manifest,
                                          sizeof(other_manifest)) == -2,
              "a DIVERGENT genesis manifest was accepted"); OK();
        /* And the converse, so the check above cannot pass by refusing
         * everything: presenting the manifest that WAS committed still
         * succeeds. */
        CHECK(v2x_genesis_min(fx.w, vset, NULL, NULL) == 0,
              "the committed manifest must still be accepted"); OK();

        /* O15A (reviewer NOTE): the manifest cannot be OMITTED to skip
         * the divergence check. A caller that presents no manifest
         * cannot assert agreement with the committed one, so it is
         * refused on the idempotent path exactly as on a fresh chain —
         * previously this returned SUCCESS and bypassed the check. */
        CHECK(nodus_witness_v2_genesis(fx.w, NULL, vset, 0) == -1,
              "a no-manifest genesis must be refused even once genesis "
              "is already committed"); OK();
    }
    /* A genesis asserting a DIFFERENT id than the committed one. */
    uint8_t gen_id2[64];
    memcpy(gen_id2, gen_id, 64);
    gen_id2[0] ^= 1;
    CHECK(nodus_witness_v2_genesis_ex(fx.w, gen_id2, vset, 0,
                                      (const uint8_t *)"x", 1) == -2,
          "conflicting genesis accepted"); OK();

    dna_domain_manifest_t sys_man, core_man;
    CHECK(nodus_witness_domreg_get(fx.w, 0, NULL, &sys_man, NULL) == 0,
          "get sys man");
    CHECK(nodus_witness_domreg_get(fx.w, 1, NULL, &core_man, NULL) == 0,
          "get core man");
    uint8_t zero64[64];
    memset(zero64, 0, 64);
    CHECK(memcmp(sys_man.genesis_state_root, zero64, 64) != 0,
          "SYSTEM gsr is a zero placeholder"); OK();
    CHECK(memcmp(core_man.genesis_state_root, zero64, 64) != 0,
          "CORE gsr is a zero placeholder"); OK();
    CHECK(memcmp(sys_man.genesis_state_root, sys_payload_pre, 64) == 0,
          "SYSTEM gsr != payload root"); OK();
    CHECK(memcmp(core_man.genesis_state_root, core_pre, 64) == 0,
          "CORE gsr != core payload root"); OK();

    /* stored roots equal an independent full recomputation */
    {
        uint8_t sys_full[64];
        CHECK(nodus_witness_system_root_v2(fx.w, sys_full) == 0,
              "sys full");
        CHECK(memcmp(sys_full, sys_payload_pre, 64) != 0,
              "final root did not commit the registry"); OK();
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "SELECT head FROM v2_domain_heads WHERE domain_id=0",
              -1, &st, NULL) == SQLITE_OK, "prep");
        CHECK(sqlite3_step(st) == SQLITE_ROW, "sys head row");
        uint8_t stored_sys[64];
        memcpy(stored_sys,
               (const uint8_t *)sqlite3_column_blob(st, 0) + 4, 64);
        sqlite3_finalize(st);
        CHECK(memcmp(stored_sys, sys_full, 64) == 0,
              "stored SYSTEM head != full recomputation"); OK();
        uint8_t stored_d[64], stored_g[64];
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "SELECT domains_root, global_root FROM v2_blocks WHERE "
              "global_height=0", -1, &st, NULL) == SQLITE_OK, "prep");
        CHECK(sqlite3_step(st) == SQLITE_ROW, "gen row");
        memcpy(stored_d, sqlite3_column_blob(st, 0), 64);
        memcpy(stored_g, sqlite3_column_blob(st, 1), 64);
        sqlite3_finalize(st);
        uint8_t re_d[64], re_g[64];
        CHECK(nodus_witness_global_root_v2(fx.w, re_g, re_d, NULL, NULL)
                  == 0, "recompute");
        CHECK(memcmp(stored_d, re_d, 64) == 0 &&
              memcmp(stored_g, re_g, 64) == 0,
              "genesis roots != recomputation"); OK();
    }

    /* an INDEPENDENT second fixture lands on byte-identical roots */
    {
        fixture_t fx2;
        CHECK(fx_open(&fx2) == 0, "fx2");
        CHECK(nodus_witness_db_migrate_v2s9(fx2.w) == 0, "migrate2");
        CHECK(v2x_table_init(fx2.w) == 0, "table2");
        CHECK(v2x_genesis_min(fx2.w, vset, NULL, NULL) == 0,
              "genesis2");
        uint8_t g1[64], g2[64];
        CHECK(nodus_witness_global_root_v2(fx.w, g1, NULL, NULL, NULL)
                  == 0 &&
              nodus_witness_global_root_v2(fx2.w, g2, NULL, NULL, NULL)
                  == 0 && memcmp(g1, g2, 64) == 0,
              "independent genesis roots diverged"); OK();
        fx_close(&fx2);
    }

    /* ── 2+3. heads / updates / replay ──────────────────────────────── */
    uint64_t h_sys = 9, h_core = 9;
    CHECK(head_height(fx.w, 0, &h_sys) == 0 && h_sys == 0, "sys h0"); OK();
    CHECK(head_height(fx.w, 1, &h_core) == 0 && h_core == 0, "core h0");
    OK();

    /* block 1: CORE-only */
    static v2x_env_t e1;
    CHECK(env_core_utxo_create(&e1, 0x01, 100) == 0, "env1");
    nodus_v2_envelope_t v1 = { e1.bytes, e1.len };
    nodus_v2_block_t b1;
    mk_block(&b1, 1, &v1, 1);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b1) == 0, "block 1"); OK();
    CHECK(q1(fx.w, "SELECT amount FROM utxo_set WHERE "
                   "nullifier=CAST(zeroblob(63)||x'01' AS BLOB)") == 100,
          "typed effect did not land"); OK();
    CHECK(head_height(fx.w, 0, &h_sys) == 0 && h_sys == 0,
          "SYSTEM advanced while untouched"); OK();
    CHECK(head_height(fx.w, 1, &h_core) == 0 && h_core == 1, "core h1");
    OK();
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_domain_updates "
                   "WHERE global_height=1") == 1,
          "block1 must carry exactly one update"); OK();
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_root_history "
                   "WHERE domain_id=1 AND domain_height=1") == 1,
          "history row missing"); OK();
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_root_history "
                   "WHERE domain_id=0 AND domain_height>0") == 0,
          "phantom SYSTEM history"); OK();

    /* replay matrix */
    uint8_t dg[64], dg2[64];
    CHECK(db_state_digest(fx.w, dg) == 0, "digest");
    /* The id block 1 actually committed — ENGINE-derived, not chosen. */
    uint8_t b1_id[64];
    memcpy(b1_id, b1.out_block_id, 64);

    /* FOLLOWER-MODE idempotent replay: asserting the committed id at the
     * committed height is the ONLY way to reach rc 1. The engine serves
     * the stored identity back without re-executing. */
    nodus_v2_block_t rb = b1;
    rb.expect_block_id = b1_id;
    CHECK(nodus_witness_v2_apply_block(fx.w, &rb) == 1,
          "identical replay not idempotent"); OK();
    CHECK(memcmp(rb.out_block_id, b1_id, 64) == 0,
          "rc1 did not serve the committed id"); OK();
    CHECK(db_state_digest(fx.w, dg2) == 0 && memcmp(dg, dg2, 64) == 0,
          "idempotent replay wrote state"); OK();

    /* LEADER MODE at an already-committed height has NO fast path (D6):
     * with nothing asserted there is no id to probe with, so it dies on
     * height continuity instead. The asymmetry is deliberate — both arms
     * refuse to write, which is the property that matters. */
    rb = b1;
    rb.expect_block_id = NULL;
    CHECK(nodus_witness_v2_apply_block(fx.w, &rb) == -1,
          "leader-mode committed height accepted"); OK();

    uint8_t bad_id[64];
    memcpy(bad_id, b1_id, 64);
    bad_id[0] ^= 1;                            /* same height, diff id  */
    rb = b1;
    rb.expect_block_id = bad_id;
    CHECK(nodus_witness_v2_apply_block(fx.w, &rb) == -1,
          "conflicting height accepted"); OK();

    static v2x_env_t ex;
    CHECK(env_core_utxo_create(&ex, 0x0f, 5) == 0, "envx");
    nodus_v2_envelope_t vx = { ex.bytes, ex.len };
    nodus_v2_block_t bx;
    /* O15A: a height GAP is NOT a verdict. The block may be perfectly
     * valid — this node just lacks its predecessors — so it must come
     * back as NOT_YET_LINKABLE and must be distinguishable from an
     * invalid block. Asserting the exact class (not merely "non-zero")
     * is the point: under the old contract this returned the same -1 as
     * a genuinely invalid block, and no test could tell them apart. */
    mk_block(&bx, 3, &vx, 1);                  /* gap                    */
    CHECK(nodus_witness_v2_apply_block(fx.w, &bx) == NODUS_V2_NOT_YET_LINKABLE,
          "height gap must be NOT_YET_LINKABLE, not a verdict");
    OK();

    /* ── O15A §9: the LINKAGE CLASS MATRIX ────────────────────────────
     * The whole point of the split is that these situations are told
     * apart. Asserting each by its EXACT class is what makes the suite
     * able to fail if any two are ever merged again — a `!= 0` check
     * here would pass under the very defect this closes. */
    {
        uint8_t lg[64], lg2[64];
        CHECK(db_state_digest(fx.w, lg) == 0, "linkage digest"); OK();

        /* A FAR-future height is the same class as a one-block gap:
         * still absent predecessor state, still no judgement. */
        mk_block(&bx, 1000000, &vx, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &bx)
                  == NODUS_V2_NOT_YET_LINKABLE,
              "large height gap must be NOT_YET_LINKABLE"); OK();

        /* Height 0 is a VERDICT, not a deferral, and the ordering is
         * deliberate: genesis has its own entry point, so no amount of
         * waiting for predecessors could ever make this acceptable. */
        mk_block(&bx, 0, &vx, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &bx)
                  == NODUS_V2_CONSENSUS_INVALID,
              "height 0 through apply_block must be a verdict"); OK();

        /* STALE — at or below the head — is evaluable NOW, so it earns a
         * real verdict. This is the boundary that must never drift into
         * the deferral class: a block we can already judge is judged. */
        mk_block(&bx, 1, &vx, 1);
        bx.expect_block_id = NULL;
        CHECK(nodus_witness_v2_apply_block(fx.w, &bx)
                  == NODUS_V2_CONSENSUS_INVALID,
              "stale height must stay a verdict, not NOT_YET_LINKABLE");
        OK();

        /* None of the above may touch a single byte of state. */
        CHECK(db_state_digest(fx.w, lg2) == 0 && memcmp(lg, lg2, 64) == 0,
              "linkage classification wrote state"); OK();

        /* The classifiers must agree with the values, so a future edit
         * cannot move a class between families unnoticed. */
        CHECK(!nodus_v2_result_is_verdict(NODUS_V2_NOT_YET_LINKABLE),
              "NOT_YET_LINKABLE must never be a verdict"); OK();
        CHECK(!nodus_v2_result_is_verdict(NODUS_V2_INTERNAL_FAULT),
              "INTERNAL_FAULT must never be a verdict"); OK();
        CHECK(nodus_v2_result_is_undecided(NODUS_V2_NOT_YET_LINKABLE) &&
              nodus_v2_result_is_undecided(NODUS_V2_INTERNAL_FAULT),
              "both undecided classes must classify as undecided"); OK();
        CHECK(nodus_v2_result_is_verdict(NODUS_V2_CONSENSUS_INVALID) &&
              nodus_v2_result_is_verdict(NODUS_V2_RETIRED_VERSION) &&
              nodus_v2_result_is_verdict(NODUS_V2_UNSUPPORTED_VERSION),
              "the three verdict classes must classify as verdicts"); OK();
        CHECK(!nodus_v2_result_is_accepted(NODUS_V2_NOT_YET_LINKABLE),
              "NOT_YET_LINKABLE must never count as accepted"); OK();

        /* Every class is distinct — the property the old contract could
         * not hold, since three of these shared the value -1. */
        CHECK(NODUS_V2_NOT_YET_LINKABLE != NODUS_V2_CONSENSUS_INVALID &&
              NODUS_V2_NOT_YET_LINKABLE != NODUS_V2_INTERNAL_FAULT &&
              NODUS_V2_RETIRED_VERSION  != NODUS_V2_UNSUPPORTED_VERSION &&
              NODUS_V2_RETIRED_VERSION  != NODUS_V2_CONSENSUS_INVALID,
              "result classes must be pairwise distinct"); OK();
    }
    mk_block(&bx, 2, &vx, 1);
    uint8_t wrong_prev[64];
    memset(wrong_prev, 0x5A, 64);              /* wrong prev             */
    bx.expect_prev_block_id = wrong_prev;
    CHECK(nodus_witness_v2_apply_block(fx.w, &bx) == -1,
          "wrong prev accepted"); OK();
    /* A block at height 2 asserting block 1's id: the DERIVED id cannot
     * equal it, so the assertion fails before commit. (The engine also
     * refuses a genuinely duplicate derived id in phase 13, which no
     * input can force — that is the point.) */
    mk_block(&bx, 2, &vx, 1);
    bx.expect_block_id = b1_id;
    CHECK(nodus_witness_v2_apply_block(fx.w, &bx) == -1,
          "reused BlockID accepted"); OK();
    /* wrong DECLARED epoch: the derivation is the authority */
    mk_block(&bx, 2, &vx, 1);
    bx.epoch = 1;                              /* height 2 is epoch 0    */
    CHECK(nodus_witness_v2_apply_block(fx.w, &bx) == -1,
          "wrong block epoch accepted"); OK();
    CHECK(db_state_digest(fx.w, dg2) == 0 && memcmp(dg, dg2, 64) == 0,
          "rejected blocks wrote state"); OK();

    /* block 2: SYSTEM-only */
    static v2x_env_t e2;
    CHECK(env_sys_cc(&e2, 999991, 5) == 0, "env2");
    nodus_v2_envelope_t v2 = { e2.bytes, e2.len };
    nodus_v2_block_t b2;
    mk_block(&b2, 2, &v2, 1);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b2) == 0, "block 2"); OK();
    CHECK(head_height(fx.w, 0, &h_sys) == 0 && h_sys == 1, "sys h1"); OK();
    CHECK(head_height(fx.w, 1, &h_core) == 0 && h_core == 1,
          "core advanced while untouched"); OK();

    /* block 3: two CORE txs → ONE update, DERIVED-id local indices */
    static v2x_env_t e31, e32;
    CHECK(env_core_utxo_create(&e31, 0x31, 10) == 0, "env31");
    CHECK(env_core_utxo_create(&e32, 0x32, 20) == 0, "env32");
    nodus_v2_envelope_t v3[2] = {
        { e31.bytes, e31.len }, { e32.bytes, e32.len }
    };
    /* learn the DERIVED ids through the (pure, read-only) preflight
     * seam, with the same contextual ruleset table the engine builds */
    uint8_t id31[64], id32[64];
    {
        dna_env_leg_ctx_t rs[2];
        rs[0].domain_id = 0;
        rs[0].ruleset_version = sys_man.ruleset_version;
        memcpy(rs[0].ruleset_hash, sys_man.ruleset_hash, 64);
        rs[1].domain_id = 1;
        rs[1].ruleset_version = core_man.ruleset_version;
        memcpy(rs[1].ruleset_hash, core_man.ruleset_hash, 64);
        dna_env_preflight_t *pf = calloc(2, sizeof(*pf));
        CHECK(pf != NULL, "pf alloc");
        CHECK(nodus_witness_v2_env_preflight_batch(fx.w, 3, rs, 2, v3, 2,
                                                   pf, NULL, NULL)
                  == NODUS_V2_ENV_OK, "preflight ids");
        memcpy(id31, pf[0].wire_id, 64);
        memcpy(id32, pf[1].wire_id, 64);
        free(pf);
    }
    nodus_v2_block_t b3;
    mk_block(&b3, 3, v3, 2);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b3) == 0, "block 3"); OK();
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_domain_updates "
                   "WHERE global_height=3") == 1, "one update for 2 tx");
    OK();
    {
        /* the persisted ids ARE the derived ids, in batch order */
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "SELECT tx_id, local_index FROM v2_tx_local_index WHERE "
              "domain_id=1 AND domain_height=2 ORDER BY local_index",
              -1, &st, NULL) == SQLITE_OK, "prep li");
        CHECK(sqlite3_step(st) == SQLITE_ROW &&
              sqlite3_column_bytes(st, 0) == 64 &&
              memcmp(sqlite3_column_blob(st, 0), id31, 64) == 0 &&
              sqlite3_column_int64(st, 1) == 0, "local index 0");
        CHECK(sqlite3_step(st) == SQLITE_ROW &&
              memcmp(sqlite3_column_blob(st, 0), id32, 64) == 0 &&
              sqlite3_column_int64(st, 1) == 1, "local index 1");
        CHECK(sqlite3_step(st) == SQLITE_DONE, "exactly two");
        sqlite3_finalize(st);
        OK();
    }
    /* update carries the summed ACTUAL consumed units: per envelope,
     * with every placeholder weight 1 and one 1-effect result —
     *   fixed  = w_op(1) + call_len + auth_len(1)
     *   charge = n_eff(1) + res_len
     * (no reads). call/res lengths are read back from the encoding. */
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "SELECT upd FROM v2_domain_updates WHERE global_height=3",
              -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW,
              "upd row");
        dna_domain_update_t u;
        CHECK(dna_dupd_decode(sqlite3_column_blob(st, 0),
                              (size_t)sqlite3_column_bytes(st, 0), &u) == 0,
              "upd decode");
        sqlite3_finalize(st);
        dna_env_view_t vv;
        CHECK(dna_env_decode(e31.bytes, e31.len, &vv) == 0, "dec31");
        uint64_t call_len = vv.leg[0].call_len;
        uint64_t res_len = call_len - 2;      /* script: 0 reads + tail */
        uint64_t per_env = (1 + call_len + 1) + (1 + res_len);
        CHECK(u.res_tx_count == 2 &&
              u.res_verify_cost == 2 * per_env &&
              u.old_height == 1 && u.new_height == 2,
              "update resource/height fields wrong"); OK();
    }

    /* declared no-op rejects (empty typed result, no fake updates) */
    CHECK(db_state_digest(fx.w, dg) == 0, "digest");
    static v2x_env_t enoop;
    CHECK(env_core_empty(&enoop) == 0, "enoop");
    nodus_v2_envelope_t vnoop = { enoop.bytes, enoop.len };
    nodus_v2_block_t b4;
    mk_block(&b4, 4, &vnoop, 1);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b4) == -1,
          "declared no-op produced an update"); OK();
    /* undeclared mutation rejects (adapter domain-escape caught by the
     * untouched-domain guard) */
    rogue_table_arm(fx.w);
    static v2x_env_t erogue;
    CHECK(env_sys_cc(&erogue, 999992, 5) == 0, "erogue");
    nodus_v2_envelope_t vrogue = { erogue.bytes, erogue.len };
    mk_block(&b4, 4, &vrogue, 1);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b4) == -1,
          "undeclared CORE mutation accepted"); OK();
    rogue_table_disarm(fx.w);
    /* wrong expected root rejects */
    static v2x_env_t eok4;
    CHECK(env_core_utxo_create(&eok4, 0x42, 5) == 0, "eok4");
    nodus_v2_envelope_t vok4 = { eok4.bytes, eok4.len };
    mk_block(&b4, 4, &vok4, 1);
    uint8_t bad_root[64];
    memset(bad_root, 0xDD, 64);
    b4.expect_global_root = bad_root;
    CHECK(nodus_witness_v2_apply_block(fx.w, &b4) == -1,
          "wrong expected root accepted"); OK();
    CHECK(db_state_digest(fx.w, dg2) == 0 && memcmp(dg, dg2, 64) == 0,
          "rejected block 4 candidates wrote state"); OK();

    /* ── 4. cross-domain atomicity ──────────────────────────────────── */
    static v2x_env_t ecross;
    CHECK(env_cross_cc_utxo(&ecross, 999992, 0x50, 30) == 0, "ecross");
    nodus_v2_envelope_t vcross = { ecross.bytes, ecross.len };
    nodus_v2_block_t b4c;
    mk_block(&b4c, 4, &vcross, 1);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b4c) == 0, "cross block");
    OK();
    CHECK(head_height(fx.w, 0, &h_sys) == 0 && h_sys == 2 &&
          head_height(fx.w, 1, &h_core) == 0 && h_core == 3,
          "cross block heights"); OK();
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_domain_updates "
                   "WHERE global_height=4") == 2, "two updates"); OK();
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_tx_index WHERE "
                   "global_height=4") == 1 &&
          q1(fx.w, "SELECT COUNT(*) FROM v2_tx_local_index WHERE "
                   "domain_height=3 AND domain_id=1") +
          q1(fx.w, "SELECT COUNT(*) FROM v2_tx_local_index WHERE "
                   "domain_height=2 AND domain_id=0") == 2,
          "one identity, two local indices"); OK();

    /* fault after SYSTEM phase / after CORE batch → NEITHER commits */
    CHECK(db_state_digest(fx.w, dg) == 0, "digest");
    static v2x_env_t ecross2;
    CHECK(env_cross_cc_utxo(&ecross2, 999993, 0x51, 40) == 0, "ecross2");
    nodus_v2_envelope_t vcross2 = { ecross2.bytes, ecross2.len };
    nodus_v2_block_t b5;
    mk_block(&b5, 5, &vcross2, 1);
    b5.fail_at = V2AP_FAIL_AFTER_SYSTEM;
    CHECK(nodus_witness_v2_apply_block(fx.w, &b5) == -1, "F2 cross");
    CHECK(db_state_digest(fx.w, dg2) == 0 && memcmp(dg, dg2, 64) == 0,
          "SYSTEM half survived"); OK();
    mk_block(&b5, 5, &vcross2, 1);
    b5.fail_at = V2AP_FAIL_AFTER_DOMAIN_BATCH;
    b5.fail_domain_batch = 1;
    CHECK(nodus_witness_v2_apply_block(fx.w, &b5) == -1, "F4 cross");
    CHECK(db_state_digest(fx.w, dg2) == 0 && memcmp(dg, dg2, 64) == 0,
          "CORE half survived"); OK();

    /* ── 5. fault injection F1..F14 + F26/F27 (rich block), then F15 ── */
    static v2x_env_t er1, er2, er3;
    CHECK(env_sys_cc(&er1, 999994, 5) == 0, "er1");
    CHECK(env_cross_cc_utxo(&er2, 999995, 0x62, 11) == 0, "er2");
    CHECK(env_core_utxo_create(&er3, 0x63, 12) == 0, "er3");
    nodus_v2_envelope_t rich[3] = {
        { er1.bytes, er1.len }, { er2.bytes, er2.len },
        { er3.bytes, er3.len }
    };
    for (int f = V2AP_FAIL_AFTER_BEGIN; f <= V2AP_FAIL_COMMIT; f++) {
        nodus_v2_block_t bf;
        mk_block(&bf, 5, rich, 3);
        bf.fail_at = (nodus_v2_apply_fail_t)f;
        bf.fail_domain_batch = 1;
        CHECK(nodus_witness_v2_apply_block(fx.w, &bf) == -1,
              "fault point did not fail");
        CHECK(db_state_digest(fx.w, dg2) == 0 &&
              memcmp(dg, dg2, 64) == 0, "fault point leaked state");
    }
    OK();
    /* F26: whole batch reserved, then abort — nothing persists and the
     * next run of the same block succeeds (budget restoration proven
     * observationally: a stranded reservation would starve it) */
    {
        nodus_v2_block_t bf;
        mk_block(&bf, 5, rich, 3);
        bf.fail_at = V2AP_FAIL_AFTER_ENV_RESERVE;
        CHECK(nodus_witness_v2_apply_block(fx.w, &bf) == -1, "F26 rc");
        CHECK(db_state_digest(fx.w, dg2) == 0 &&
              memcmp(dg, dg2, 64) == 0, "F26 leaked state"); OK();
        mk_block(&bf, 5, rich, 3);
        bf.fail_at = V2AP_FAIL_AFTER_ENV_EXEC;
        bf.fail_env_index = 1;
        CHECK(nodus_witness_v2_apply_block(fx.w, &bf) == -1, "F27 rc");
        CHECK(db_state_digest(fx.w, dg2) == 0 &&
              memcmp(dg, dg2, 64) == 0, "F27 leaked state"); OK();
    }
    /* F15: committed, pre-cache crash window */
    nodus_v2_block_t b5f;
    mk_block(&b5f, 5, rich, 3);
    b5f.fail_at = V2AP_FAIL_AFTER_COMMIT;
    CHECK(nodus_witness_v2_apply_block(fx.w, &b5f) == 2, "F15 rc"); OK();
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_blocks WHERE global_height=5")
              == 1, "F15 not committed"); OK();
    uint8_t dg_committed[64];
    CHECK(db_state_digest(fx.w, dg_committed) == 0, "digest");
    CHECK(fx_reopen(&fx) == 0, "reopen after F15");
    CHECK(db_state_digest(fx.w, dg2) == 0 &&
          memcmp(dg_committed, dg2, 64) == 0,
          "restart lost committed state"); OK();
    /* O14 D6 + §15 restart/recompute: after the crash window and a
     * reopen, replaying the SAME block against the id the engine derived
     * before the crash is the idempotent no-write path, and the engine
     * serves that stored identity back from the committed row. */
    uint8_t id5[64];
    CHECK(v2x_block_id_at(fx.w, 5, id5) == 0, "read committed id5");
    nodus_v2_block_t b5r;
    mk_block(&b5r, 5, rich, 3);
    b5r.expect_block_id = id5;
    CHECK(nodus_witness_v2_apply_block(fx.w, &b5r) == 1,
          "post-crash replay applied twice"); OK();
    CHECK(memcmp(b5r.out_block_id, id5, 64) == 0,
          "restart served a different identity"); OK();

    /* ── 6. resource limits ─────────────────────────────────────────── */
    CHECK(db_state_digest(fx.w, dg) == 0, "digest");
    {   /* global tx cap (10) */
        static v2x_env_t many[11];
        nodus_v2_envelope_t vm[11];
        for (int i = 0; i < 11; i++) {
            CHECK(env_core_utxo_create(&many[i], (uint8_t)(0x70 + i), 1)
                      == 0, "env many");
            vm[i].env_bytes = many[i].bytes;
            vm[i].env_len = many[i].len;
        }
        nodus_v2_block_t bm;
        mk_block(&bm, 6, vm, 11);
        CHECK(nodus_witness_v2_apply_block(fx.w, &bm) == -1,
              "global tx cap ignored"); OK();
    }
    {   /* global UNIT budget: a reservation ceiling the block budget
         * cannot cover rejects at reserve */
        uint8_t key[64] = { 0 };
        key[63] = 0x7F;
        uint8_t val[8];
        v2x_put64(val, 1);
        uint8_t res[512];
        size_t rl = 0;
        CHECK(v2x_eff1(res, sizeof(res), V2X_OP_UTXO, DNA_EFFECT_CREATE,
                       DNA_EFFECT_PRE_ABSENT, key, 64, val, 8, &rl) == 0,
              "res");
        uint8_t call[600];
        uint32_t cl = v2x_script_build(call, sizeof(call), NULL, 0, res,
                                       rl);
        CHECK(cl != 0, "call");
        v2x_leg_t leg = { 1, 1, call, cl, 4, 2048 };
        static v2x_env_t ebig;
        CHECK(v2x_env_build_ex(&ebig, (uint64_t)NODUS_V2_GLOBAL_UNIT_BUDGET
                               + 1, 0, 0, &leg, 1) == 0, "ebig");
        nodus_v2_envelope_t vb = { ebig.bytes, ebig.len };
        nodus_v2_block_t bb;
        mk_block(&bb, 6, &vb, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &bb) == -1,
              "global unit budget ignored"); OK();
    }
    {   /* per-domain quota + unit budget via a CONSISTENT
         * fixture-written CORE manifest */
        dna_domain_manifest_t qman = core_man;
        qman.quota_tx_per_block = 1;
        qman.quota_verify_cost = 0;      /* tx-count quota only first    */
        uint8_t enc[DNA_DOMMAN_MAX_ENC_LEN], mh[64];
        size_t el = 0;
        dna_domreg_record_t rec;
        uint8_t recb[DNA_DOMREG_REC_ENC_LEN];
        sqlite3_stmt *st = NULL;
#define WRITE_CORE_MAN(M) do { \
        CHECK(dna_domman_encode((M), enc, sizeof(enc), &el) == 0, "enc"); \
        CHECK(dna_domman_hash((M), mh) == 0, "hash"); \
        CHECK(nodus_witness_domreg_get(fx.w, 1, &rec, NULL, NULL) == 0, \
              "rec"); \
        memcpy(rec.current_manifest_hash, mh, 64); \
        CHECK(dna_domreg_record_encode(&rec, recb) == 0, "recb"); \
        CHECK(sqlite3_prepare_v2(fx.w->db, \
              "UPDATE domain_registry SET record=?1, current_manifest=?2 " \
              "WHERE domain_id=1", -1, &st, NULL) == SQLITE_OK, "prep"); \
        sqlite3_bind_blob(st, 1, recb, sizeof(recb), SQLITE_TRANSIENT); \
        sqlite3_bind_blob(st, 2, enc, (int)el, SQLITE_TRANSIENT); \
        CHECK(sqlite3_step(st) == SQLITE_DONE, "update"); \
        sqlite3_finalize(st); \
} while (0)
        WRITE_CORE_MAN(&qman);

        static v2x_env_t eq1, eq2;
        CHECK(env_core_utxo_create(&eq1, 0x81, 1) == 0, "eq1");
        CHECK(env_core_utxo_create(&eq2, 0x82, 1) == 0, "eq2");
        nodus_v2_envelope_t vq[2] = {
            { eq1.bytes, eq1.len }, { eq2.bytes, eq2.len }
        };
        nodus_v2_block_t bq;
        mk_block(&bq, 6, vq, 2);
        CHECK(nodus_witness_v2_apply_block(fx.w, &bq) == -1,
              "per-domain tx quota ignored"); OK();

        /* per-domain UNIT budget: quota_verify_cost is the committed
         * per-block unit budget — 5 units cannot cover any real leg's
         * static reservation */
        qman.quota_tx_per_block = 0;
        qman.quota_verify_cost = 5;
        WRITE_CORE_MAN(&qman);
        static v2x_env_t eqc;
        CHECK(env_core_utxo_create(&eqc, 0x83, 1) == 0, "eqc");
        nodus_v2_envelope_t vqc = { eqc.bytes, eqc.len };
        mk_block(&bq, 6, &vqc, 1);
        CHECK(nodus_witness_v2_apply_block(fx.w, &bq) == -1,
              "per-domain unit budget ignored"); OK();
        /* restore the genesis manifest (consistent again) */
        WRITE_CORE_MAN(&core_man);
#undef WRITE_CORE_MAN
    }
    CHECK(db_state_digest(fx.w, dg2) == 0 && memcmp(dg, dg2, 64) == 0,
          "resource rejections leaked state"); OK();
    fx_close(&fx);

    /* ── 7. supply (official DNA numbers) ───────────────────────────── */
    /* O15J — this is the ONE section of this file that tests the
     * conservation equation ITSELF. The fixture arms a test-only bypass
     * on EVERY v2x_genesis_min call (:461, :464, :485, :561 above), and
     * from here to the end of the run this file asserts things about the
     * live invariant, so it is disarmed once here.
     *
     * CORRECTED after review R1: an earlier version of this comment said
     * the negative assertions (`supply_check(...) != 0`, e.g. the
     * additive-70M case below) would "pass trivially" with the bypass
     * armed. That is the wrong polarity — an armed bypass returns 0, so
     * those assertions FAIL loudly rather than passing. What the disarm
     * actually protects are the ~15 POSITIVE assertions in this section
     * (`supply_check(...) == 0`), which an armed bypass satisfies
     * unconditionally and which would therefore prove nothing. */
    nodus_witness_v2_supply_test_bypass(0);

    fixture_t fs;
    CHECK(fx_open(&fs) == 0, "supply fixture"); OK();
    CHECK(nodus_witness_db_migrate_v2s9(fs.w) == 0, "migrate");
    CHECK(v2x_table_init(fs.w) == 0, "scripted table (supply)");

    CHECK(run_sql(fs.w->db,
        "INSERT INTO supply_tracking (id, genesis_supply, total_burned, "
        "total_minted, current_supply, last_tx_hash, last_sequence) "
        "VALUES (1, 100000000000000000, 0, 0, 100000000000000000, "
        "x'00', 0)") == 0, "supply row"); OK();
    for (int i = 0; i < 7; i++) {
        char sql[640];
        snprintf(sql, sizeof(sql),
            "INSERT INTO validators (pubkey_hash, pubkey, self_stake, "
            "total_delegated, commission_bps, status, active_since_block, "
            "unstake_destination_fp, unstake_destination_pubkey) "
            "VALUES (zeroblob(63)||x'%02x', zeroblob(2591)||x'%02x', "
            "1000000000000000, 0, 100, 0, 0, 'fp%d', zeroblob(2592))",
            0xA0 + i, 0xB0 + i, i);
        CHECK(run_sql(fs.w->db, sql) == 0, "validator");
    }
    CHECK(run_sql(fs.w->db,
        "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
        "tx_hash, output_index, block_height, created_at, unlock_block, "
        "domain_id) "
        "VALUES (CAST(zeroblob(63)||x'01' AS BLOB), 'genesis', 93000000000000000, "
        "zeroblob(64), zeroblob(63)||x'aa', 0, 0, 0, 0, 1)") == 0,
        "930M utxo");
    CHECK(nodus_witness_v2_supply_check(fs.w) == 0,
          "official 1B/70M carve-out does not conserve"); OK();

    /* ADDITIVE 70M (on top of 1B) must violate */
    CHECK(run_sql(fs.w->db,
        "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
        "tx_hash, output_index, block_height, created_at, unlock_block, "
        "domain_id) "
        "VALUES (CAST(zeroblob(63)||x'02' AS BLOB), 'bogus', 7000000000000000, "
        "zeroblob(64), zeroblob(63)||x'bb', 0, 0, 0, 0, 1)") == 0,
        "additive");
    CHECK(nodus_witness_v2_supply_check(fs.w) != 0,
          "additive 70M conserved"); OK();
    CHECK(run_sql(fs.w->db,
        "DELETE FROM utxo_set WHERE nullifier=CAST(zeroblob(63)||x'02' AS BLOB)") == 0, "undo");
    CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "restore"); OK();

    /* transparent → self-bond lock (move, no mint) + unlock */
    CHECK(run_sql(fs.w->db,
        "UPDATE utxo_set SET amount = amount - 1000000000000000 "
        "WHERE nullifier=CAST(zeroblob(63)||x'01' AS BLOB);"
        "UPDATE validators SET self_stake = self_stake + 1000000000000000 "
        "WHERE pubkey_hash=zeroblob(63)||x'a0'") == 0, "lock");
    CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "bond lock broke"); OK();
    CHECK(run_sql(fs.w->db,
        "UPDATE validators SET self_stake = self_stake - 1000000000000000 "
        "WHERE pubkey_hash=zeroblob(63)||x'a0';"
        "UPDATE utxo_set SET amount = amount + 1000000000000000 "
        "WHERE nullifier=CAST(zeroblob(63)||x'01' AS BLOB)") == 0, "unlock");
    CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "unlock broke"); OK();
    /* delegation lock (classification change, not total) */
    CHECK(run_sql(fs.w->db,
        "UPDATE utxo_set SET amount = amount - 10000000000 "
        "WHERE nullifier=CAST(zeroblob(63)||x'01' AS BLOB);"
        "UPDATE validators SET total_delegated = total_delegated + "
        "10000000000 WHERE pubkey_hash=zeroblob(63)||x'a1'") == 0, "delegate");
    CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "delegation broke");
    OK();
    /* fee burn EXACTLY once */
    CHECK(run_sql(fs.w->db,
        "UPDATE utxo_set SET amount = amount - 1000000 "
        "WHERE nullifier=CAST(zeroblob(63)||x'01' AS BLOB);"
        "UPDATE supply_tracking SET total_burned = total_burned + 1000000")
        == 0, "burn");
    CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "single burn broke");
    OK();
    CHECK(run_sql(fs.w->db,
        "UPDATE supply_tracking SET total_burned = total_burned + 1000000")
        == 0, "double burn");
    CHECK(nodus_witness_v2_supply_check(fs.w) != 0,
          "fee processed twice conserved"); OK();
    CHECK(run_sql(fs.w->db,
        "UPDATE supply_tracking SET total_burned = total_burned - 1000000")
        == 0, "undo double");
    /* reward: mint into the epoch pool, then settle pool → utxo */
    CHECK(run_sql(fs.w->db,
        "UPDATE supply_tracking SET total_minted = total_minted + 3200;"
        "INSERT INTO epoch_state (epoch_start_height, epoch_pool_accum, "
        "snapshot_hash) VALUES (0, 3200, zeroblob(64))") == 0, "mint");
    CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "mint broke"); OK();
    CHECK(run_sql(fs.w->db,
        "UPDATE epoch_state SET epoch_pool_accum = 0 "
        "WHERE epoch_start_height = 0;"
        "UPDATE utxo_set SET amount = amount + 3200 "
        "WHERE nullifier=CAST(zeroblob(63)||x'01' AS BLOB)") == 0, "settle");
    CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "settle broke"); OK();
    /* duplicate ownership: value in a UTXO AND a bond simultaneously */
    CHECK(run_sql(fs.w->db,
        "UPDATE validators SET self_stake = self_stake + 5 "
        "WHERE pubkey_hash=zeroblob(63)||x'a2'") == 0, "dup owner");
    CHECK(nodus_witness_v2_supply_check(fs.w) != 0,
          "double-counted value conserved"); OK();
    CHECK(run_sql(fs.w->db,
        "UPDATE validators SET self_stake = self_stake - 5 "
        "WHERE pubkey_hash=zeroblob(63)||x'a2'") == 0, "undo");
    /* missing ownership */
    CHECK(run_sql(fs.w->db,
        "UPDATE utxo_set SET amount = amount - 5 WHERE nullifier=CAST(zeroblob(63)||x'01' AS BLOB)")
        == 0, "vanish");
    CHECK(nodus_witness_v2_supply_check(fs.w) != 0, "vanished conserved");
    OK();
    CHECK(run_sql(fs.w->db,
        "UPDATE utxo_set SET amount = amount + 5 WHERE nullifier=CAST(zeroblob(63)||x'01' AS BLOB)")
        == 0, "undo");
    /* underflow / overflow */
    CHECK(run_sql(fs.w->db,
        "UPDATE supply_tracking SET total_burned = 200000000000000001")
        == 0, "uf");
    CHECK(nodus_witness_v2_supply_check(fs.w) != 0, "underflow passed");
    OK();
    CHECK(run_sql(fs.w->db,
        "UPDATE supply_tracking SET total_burned = 1000000, "
        "total_minted = 18446744073709551615") == 0, "of");
    CHECK(nodus_witness_v2_supply_check(fs.w) != 0, "overflow passed");
    OK();
    CHECK(run_sql(fs.w->db,
        "UPDATE supply_tracking SET total_minted = 3200") == 0, "restore");
    CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "restore broke"); OK();
    /* unbacked native pool balance must fail the equation */
    CHECK(run_sql(fs.w->db,
        "INSERT INTO v2_pools (domain_id, pool_id, config_version, "
        "tree_depth, history_limit, asset_ref, note_count, note_root, "
        "frontier, nul_count, nul_root, balance, hist_count, "
        "hist_next_seq) VALUES (1, 9, 1, 24, 720, zeroblob(64), 0, "
        "zeroblob(32), zeroblob(768), 0, zeroblob(64), 5, 1, 1)") == 0,
          "mk pool row");
    CHECK(nodus_witness_v2_supply_check(fs.w) != 0,
          "unbacked pool balance tolerated"); OK();
    CHECK(run_sql(fs.w->db,
        "UPDATE v2_pools SET balance = 0 WHERE pool_id = 9") == 0,
          "zero pool");
    CHECK(nodus_witness_v2_supply_check(fs.w) == 0,
          "zero pool balance broke conservation"); OK();
    CHECK(run_sql(fs.w->db, "DELETE FROM v2_pools WHERE pool_id = 9")
          == 0, "drop pool row");
    /* restart invariant */
    CHECK(fx_reopen(&fs) == 0, "reopen");
    CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "restart broke"); OK();

    /* an engine block that BREAKS supply rolls back completely */
    CHECK(v2x_genesis_min(fs.w, vset, NULL, NULL) == 0,
          "supply-fixture genesis"); OK();
    /* O15J — v2x_genesis_min RE-ARMS the test-only bypass on every call,
     * so it must be disarmed again here.
     *
     * CORRECTED after review R1: with the bypass live the two assertions
     * below (`apply_block == -1` and the unchanged-digest check) would
     * FAIL, not become vacuous — the block would commit. The disarm is
     * still required; the hazard is simply a loud failure rather than a
     * silent pass. The silent-pass hazard belongs to the positive
     * assertions after this point. */
    nodus_witness_v2_supply_test_bypass(0);
    uint8_t sdg[64], sdg2[64];
    CHECK(db_state_digest(fs.w, sdg) == 0, "digest");
    static v2x_env_t einf;
    CHECK(env_core_utxo_create(&einf, 0x90, 999) == 0, "einf");
    nodus_v2_envelope_t vinf = { einf.bytes, einf.len };
    nodus_v2_block_t sb;
    mk_block(&sb, 1, &vinf, 1);
    CHECK(nodus_witness_v2_apply_block(fs.w, &sb) == -1,
          "supply-breaking block accepted"); OK();
    CHECK(db_state_digest(fs.w, sdg2) == 0 && memcmp(sdg, sdg2, 64) == 0,
          "supply-breaking block leaked state"); OK();

    /* ── 8. SUPPLY OWNERSHIP through TYPED cross-domain envelopes ───── */
    {
        /* (a) MINT: total_minted (CORE, SUPPLY_SET absolute) + epoch
         * pool (SYSTEM, EPOCH_SET absolute) — one cross-domain
         * envelope, two DomainUpdates, conserved. */
        uint64_t minted = q1(fs.w, "SELECT total_minted FROM "
                                   "supply_tracking");
        uint64_t accum = q1(fs.w, "SELECT epoch_pool_accum FROM "
                                  "epoch_state WHERE epoch_start_height=0");
        uint8_t skey[8], sval[8], ckey[1] = { 1 }, cval[8];
        v2x_put64(skey, 0);
        v2x_put64(sval, accum + 500);
        v2x_put64(cval, minted + 500);
        uint8_t sres[256], cres[256];
        size_t srl = 0, crl = 0;
        CHECK(v2x_eff1(sres, sizeof(sres), V2X_OP_EPOCH, DNA_EFFECT_SET,
                       DNA_EFFECT_PRE_EXISTS, skey, 8, sval, 8, &srl)
                  == 0, "sres");
        CHECK(v2x_eff1(cres, sizeof(cres), V2X_OP_SUPPLY, DNA_EFFECT_SET,
                       DNA_EFFECT_PRE_EXISTS, ckey, 1, cval, 8, &crl)
                  == 0, "cres");
        uint8_t scall[400], ccall[400];
        uint32_t scl = v2x_script_build(scall, sizeof(scall), NULL, 0,
                                        sres, srl);
        uint32_t ccl = v2x_script_build(ccall, sizeof(ccall), NULL, 0,
                                        cres, crl);
        CHECK(scl && ccl, "calls");
        v2x_leg_t mlegs[2] = {
            { 0, 1, scall, scl, 4, 2048 },
            { 1, 1, ccall, ccl, 4, 2048 }
        };
        static v2x_env_t emint;
        CHECK(v2x_env_build(&emint, mlegs, 2) == 0, "emint");
        nodus_v2_envelope_t vmint = { emint.bytes, emint.len };
        nodus_v2_block_t mb;
        mk_block(&mb, 1, &vmint, 1);
        CHECK(nodus_witness_v2_apply_block(fs.w, &mb) == 0, "mint block");
        CHECK(q1(fs.w, "SELECT COUNT(*) FROM v2_domain_updates "
                       "WHERE global_height=1") == 2,
              "mint must update BOTH domains atomically"); OK();
        CHECK(q1(fs.w, "SELECT total_minted FROM supply_tracking")
                  == minted + 500, "minted exactly once");
        CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "mint conserves");
        OK();

        /* (b) SETTLE: pool (SYSTEM) → transparent UTXO (CORE). */
        uint64_t amt = q1(fs.w, "SELECT amount FROM utxo_set WHERE "
                                "nullifier=CAST(zeroblob(63)||x'01' AS BLOB)");
        uint8_t s2val[8], c2key[64] = { 0 }, c2val[8];
        c2key[63] = 0x01;
        v2x_put64(s2val, accum + 500 - 500);   /* back to entry accum */
        v2x_put64(c2val, amt + 500);
        uint8_t s2res[256], c2res[256];
        size_t s2rl = 0, c2rl = 0;
        CHECK(v2x_eff1(s2res, sizeof(s2res), V2X_OP_EPOCH,
                       DNA_EFFECT_SET, DNA_EFFECT_PRE_EXISTS, skey, 8,
                       s2val, 8, &s2rl) == 0, "s2res");
        CHECK(v2x_eff1(c2res, sizeof(c2res), V2X_OP_UTXO, DNA_EFFECT_SET,
                       DNA_EFFECT_PRE_EXISTS, c2key, 64, c2val, 8,
                       &c2rl) == 0, "c2res");
        uint8_t s2call[400], c2call[400];
        uint32_t s2cl = v2x_script_build(s2call, sizeof(s2call), NULL, 0,
                                         s2res, s2rl);
        uint32_t c2cl = v2x_script_build(c2call, sizeof(c2call), NULL, 0,
                                         c2res, c2rl);
        CHECK(s2cl && c2cl, "calls2");
        v2x_leg_t slegs[2] = {
            { 0, 1, s2call, s2cl, 4, 2048 },
            { 1, 1, c2call, c2cl, 4, 2048 }
        };
        static v2x_env_t esettle;
        CHECK(v2x_env_build(&esettle, slegs, 2) == 0, "esettle");
        nodus_v2_envelope_t vsettle = { esettle.bytes, esettle.len };
        mk_block(&mb, 2, &vsettle, 1);
        CHECK(nodus_witness_v2_apply_block(fs.w, &mb) == 0, "settle block");
        CHECK(q1(fs.w, "SELECT COUNT(*) FROM v2_domain_updates "
                       "WHERE global_height=2") == 2,
              "settle must update BOTH domains"); OK();
        CHECK(nodus_witness_v2_supply_check(fs.w) == 0,
              "cross-domain move conserves total supply"); OK();

        /* (c) BURN: CORE-LOCAL — one leg, TWO effects (utxo decrement +
         * burned counter), exactly one DomainUpdate. */
        uint64_t sys_h_burn = q1(fs.w,
            "SELECT domain_height FROM v2_domain_heads WHERE domain_id=0");
        uint64_t amt2 = q1(fs.w, "SELECT amount FROM utxo_set WHERE "
                                 "nullifier=CAST(zeroblob(63)||x'01' AS BLOB)");
        uint64_t burned = q1(fs.w, "SELECT total_burned FROM "
                                   "supply_tracking");
        uint8_t bkey[64] = { 0 }, bval[8], b2key[1] = { 2 }, b2val[8];
        bkey[63] = 0x01;
        v2x_put64(bval, amt2 - 100);
        v2x_put64(b2val, burned + 100);
        dna_effect_in_t burn_effs[2];
        memset(burn_effs, 0, sizeof(burn_effs));
        burn_effs[0].hdr.op_id = V2X_OP_UTXO;
        burn_effs[0].hdr.effect_kind = DNA_EFFECT_SET;
        burn_effs[0].hdr.precond_tag = DNA_EFFECT_PRE_EXISTS;
        burn_effs[0].hdr.key_len = 64;
        burn_effs[0].hdr.value_len = 8;
        burn_effs[0].key = bkey;
        burn_effs[0].value = bval;
        burn_effs[1].hdr.op_id = V2X_OP_SUPPLY;
        burn_effs[1].hdr.effect_kind = DNA_EFFECT_SET;
        burn_effs[1].hdr.precond_tag = DNA_EFFECT_PRE_EXISTS;
        burn_effs[1].hdr.key_len = 1;
        burn_effs[1].hdr.value_len = 8;
        burn_effs[1].key = b2key;
        burn_effs[1].value = b2val;
        uint8_t bres[512];
        size_t brl = 0;
        CHECK(v2x_effres(bres, sizeof(bres), burn_effs, 2, &brl) == 0,
              "bres");
        uint8_t bcall[700];
        uint32_t bcl = v2x_script_build(bcall, sizeof(bcall), NULL, 0,
                                        bres, brl);
        CHECK(bcl != 0, "bcall");
        v2x_leg_t bleg = { 1, 1, bcall, bcl, 4, 2048 };
        static v2x_env_t eburn;
        CHECK(v2x_env_build(&eburn, &bleg, 1) == 0, "eburn");
        nodus_v2_envelope_t vburn = { eburn.bytes, eburn.len };
        mk_block(&mb, 3, &vburn, 1);
        CHECK(nodus_witness_v2_apply_block(fs.w, &mb) == 0, "burn block");
        CHECK(q1(fs.w, "SELECT COUNT(*) FROM v2_domain_updates "
                       "WHERE global_height=3") == 1,
              "burn is CORE-local: exactly one update"); OK();
        CHECK(q1(fs.w, "SELECT domain_height FROM v2_domain_heads "
                       "WHERE domain_id=0") == sys_h_burn,
              "burn must not advance SYSTEM"); OK();
        CHECK(q1(fs.w, "SELECT total_burned FROM supply_tracking")
                  == burned + 100, "burned exactly once");
        CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "burn conserves");
        OK();

        /* (d) an adapter escape that mutates CORE without declaring it
         * trips the untouched-domain guard. */
        uint8_t g0[64], g1[64];
        CHECK(db_state_digest(fs.w, g0) == 0, "digest");
        rogue_table_arm(fs.w);
        static v2x_env_t esneak;
        CHECK(env_sys_cc(&esneak, 999997, 5) == 0, "esneak");
        nodus_v2_envelope_t vsneak = { esneak.bytes, esneak.len };
        mk_block(&mb, 4, &vsneak, 1);
        CHECK(nodus_witness_v2_apply_block(fs.w, &mb) == -1,
              "undeclared issuance mutation accepted"); OK();
        rogue_table_disarm(fs.w);
        CHECK(db_state_digest(fs.w, g1) == 0 && memcmp(g0, g1, 64) == 0,
              "undeclared issuance mutation leaked state"); OK();

        /* (e) fault during a cross-domain native move rolls BOTH
         * domains, heads, roots, accounting and metadata back. */
        uint64_t minted2 = q1(fs.w, "SELECT total_minted FROM "
                                    "supply_tracking");
        uint64_t accum2 = q1(fs.w, "SELECT epoch_pool_accum FROM "
                                   "epoch_state WHERE "
                                   "epoch_start_height=0");
        uint8_t m2sval[8], m2cval[8];
        v2x_put64(m2sval, accum2 + 9);
        v2x_put64(m2cval, minted2 + 9);
        uint8_t m2sres[256], m2cres[256];
        size_t m2srl = 0, m2crl = 0;
        CHECK(v2x_eff1(m2sres, sizeof(m2sres), V2X_OP_EPOCH,
                       DNA_EFFECT_SET, DNA_EFFECT_PRE_EXISTS, skey, 8,
                       m2sval, 8, &m2srl) == 0, "m2sres");
        CHECK(v2x_eff1(m2cres, sizeof(m2cres), V2X_OP_SUPPLY,
                       DNA_EFFECT_SET, DNA_EFFECT_PRE_EXISTS, ckey, 1,
                       m2cval, 8, &m2crl) == 0, "m2cres");
        uint8_t m2scall[400], m2ccall[400];
        uint32_t m2scl = v2x_script_build(m2scall, sizeof(m2scall), NULL,
                                          0, m2sres, m2srl);
        uint32_t m2ccl = v2x_script_build(m2ccall, sizeof(m2ccall), NULL,
                                          0, m2cres, m2crl);
        CHECK(m2scl && m2ccl, "m2 calls");
        v2x_leg_t m2legs[2] = {
            { 0, 1, m2scall, m2scl, 4, 2048 },
            { 1, 1, m2ccall, m2ccl, 4, 2048 }
        };
        static v2x_env_t emint2;
        CHECK(v2x_env_build(&emint2, m2legs, 2) == 0, "emint2");
        nodus_v2_envelope_t vmint2 = { emint2.bytes, emint2.len };
        static const nodus_v2_apply_fail_t xpts[] = {
            V2AP_FAIL_AFTER_CROSS, V2AP_FAIL_AFTER_SUPPLY_MUT,
            V2AP_FAIL_AFTER_UPDATES, V2AP_FAIL_AFTER_HEADS,
            V2AP_FAIL_AFTER_BLOCK_META, V2AP_FAIL_BEFORE_COMMIT,
            V2AP_FAIL_AFTER_ENV_RESERVE, V2AP_FAIL_AFTER_ENV_EXEC
        };
        for (size_t i = 0; i < sizeof(xpts) / sizeof(xpts[0]); i++) {
            mk_block(&mb, 4, &vmint2, 1);
            mb.fail_at = xpts[i];
            mb.fail_env_index = 0;
            CHECK(nodus_witness_v2_apply_block(fs.w, &mb) == -1,
                  "cross-move fault did not fail");
            CHECK(db_state_digest(fs.w, g1) == 0 &&
                  memcmp(g0, g1, 64) == 0,
                  "cross-move fault leaked one domain's half");
        }
        OK();
        /* determinism after failed attempts: the same block with no
         * fault commits, proving no meter/budget residue from the
         * rejected attempts survived */
        mk_block(&mb, 4, &vmint2, 1);
        CHECK(nodus_witness_v2_apply_block(fs.w, &mb) == 0,
              "post-fault clean apply"); OK();
        CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "conserved");
    }
    fx_close(&fs);

    printf("test_v2_apply: ALL %d checks passed\n", g_checks);
    return 0;
}
