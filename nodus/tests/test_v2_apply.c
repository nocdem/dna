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
 * Rollback claims are NEVER made from return codes alone: v2x_db_digest
 * (v2_genesis_fixture.h) serializes EVERY table (sorted names, rows by
 * rowid, typed column bytes, sqlite_sequence included) into one SHA3-512
 * and the tests byte-compare it around every fault point; an ITEM
 * refusal is proven with v2x_ledger_digest (every table except the
 * per-block bookkeeping the block itself writes).
 *
 * THE LANE (tokenomics-v3 P4). Every chain is a version-3 chain (the
 * seeded version-3 genesis, v2x_seed_prepare / v2x_seed_genesis) and
 * every block goes through the cometbft lane (v2x_cmt_apply — the one
 * lane nodus_witness_v2_apply_block has a production caller for): a
 * block either COMMITS with a code per item, or is a node FAULT the host
 * rolls back. There is no block-level verdict, no idempotent replay
 * (rc 1) and no post-commit crash window (rc 2).
 *
 * Sections:
 *   1. Genesis: the cometbft genesis's refusals (no manifest, a foreign
 *      validator set, any second genesis); GENESIS-ROOT CYCLE PROOF; the
 *      committed genesis root == recomputation == the document's
 *      app_hash; an independent twin lands on the same roots.
 *   2. Heads/updates: initial heads; CORE-only block (SYSTEM does not
 *      advance); SYSTEM-only block; two-tx one-update with DERIVED-id
 *      local indices; declared no-op, undeclared mutation (adapter
 *      domain-escape) and a wrong expected root — block-level checks,
 *      node FAULTs.
 *   3. Replay/linkage: the committed height again, identity assertions,
 *      a gap, height 0, a stale height, a reused block hash, a lying
 *      epoch — node FAULTs that write nothing.
 *   4. Cross-domain atomicity: one envelope with SYSTEM+CORE legs →
 *      both commit (one DERIVED identity, two local indices); a fault
 *      between its legs (F38) → the item is refused and NEITHER half
 *      survives.
 *   5. Fault injection on a rich block: every block-level point on the
 *      lane's path → FAULT, FULL DB digest byte-identical; a fault inside
 *      one item (F31) refuses only that item; restart reproduces the
 *      committed state.
 *   6. Resource limits: no item-count cap; the engine's memory ceiling
 *      (FAULT); global UNIT budget, per-domain tx quota and per-domain
 *      unit budget (item CAPACITY codes) from a consistent
 *      fixture-written CORE manifest; per-item auth verdict reuse.
 *   7. Supply (fixture 2, official DNA numbers): unchanged direct-SQL
 *      invariant matrix + engine blocks (mint/pool/burn/sneak/fault
 *      matrix) driven through typed effects.
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

/* tokenomics-v3 P4: the SEEDED VERSION-3 GENESIS (v2_genesis_fixture.h
 * v2x_seed_prepare / v2x_seed_genesis) — the derivation's own steps with
 * the test's genesis rows seeded before the engine genesis — because
 * section 1 captures the payload roots BETWEEN the rows and the
 * registry, which the ceremony's one-call derivation cannot expose, and
 * section 7 seeds its official-numbers state before genesis. Salt 0 for
 * every fixture, so twin fixtures are the same chain. */
static int fx_open(fixture_t *fx) {
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_apply_XXXXXX");
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain_id16, 0x33, sizeof(fx->chain_id16));
    if (v2x_seed_prepare(fx->w, fx->chain_id16, 0) != 0) {
        if (fx->w->db) sqlite3_close(fx->w->db);
        rmrf(fx->dir); free(fx->w); fx->w = NULL;
        return -1;
    }
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

/* ── block + envelope helpers ───────────────────────────────────────── */
/* A block as nodus_cmt_app_finalize_block hands it to the engine: height,
 * the DERIVED epoch, the items. The cometbft-lane identity (block hash,
 * validators hash, results) is filled by v2x_cmt_apply; the ledger
 * derives no identity of its own in this lane. The whole-database
 * rollback oracle is v2x_db_digest (v2_genesis_fixture.h). */
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

/* R3 W4-C delta 3: same leg shape as env_core_utxo_create, but with a
 * caller-chosen res_max_total_units instead of v2x_env_build's default
 * 200000. Needed because the reservation formula (res_meter.h:84-87)
 * takes the FULL declared ceiling from NODUS_V2_GLOBAL_UNIT_BUDGET
 * (nodus_witness_v2_apply.h) at reserve — at the trial-B value 2097152
 * (operator 2026-09-24; 1000000 before, when 5 already exhausted it)
 * 200000 x 11 = 2200000 still exceeds it, so a block of 11 such
 * envelopes needs a smaller per-envelope ceiling to fit at all (§6
 * derives it from the macro: `ceil11`). The floor this ceiling must
 * clear is static_units(envelope):
 * sys_policy_build's seven weights are all 1
 * (nodus_witness_runtime.c:120-121), and this leg's cost is w_base(1) +
 * w_op(1) + w_callbyte*call_len + w_authbyte*auth_len(1) +
 * w_effect*max_effects(4) + w_effectbyte*max_effect_bytes(2048), where
 * call_len is 2 (the read-count header) plus the ONE-effect result's
 * wire size DNA_EFFECT_FIXED_HEAD(23) + DNA_EFFECT_RECORD_LEN(84) +
 * key(64) + value(8) = 179 (effect_wire.h:169-170) — call_len 181,
 * total 2236 units. `ceiling` must stay above that floor. */
static int env_core_utxo_create_ceiling(v2x_env_t *e, uint8_t keylast,
                                        uint64_t amount, uint64_t ceiling) {
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
    return v2x_env_build_ex(e, ceiling, 0, 0, &leg, 1);
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

/* P4 fix round — the per-item "left no identity" check. Only an APPLIED
 * item is indexed (cmt_item_index, nodus_witness_v2_apply.c, called after
 * a successful exec inside the item's savepoint), and its global_index
 * counts APPLIED items only. So a block whose refused items left nothing
 * behind has EXACTLY `applied` rows at its height in BOTH identity
 * indices (the wire index and the intent index CheckTx and the replay
 * guard read). 0 / -1. */
static int idx_rows_are(nodus_witness_t *w, uint64_t h, uint64_t applied) {
    char sql[160];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM v2_tx_index WHERE "
             "global_height = %llu", (unsigned long long)h);
    if (q1(w, sql) != applied) return -1;
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM v2_intent_index "
             "WHERE global_height = %llu", (unsigned long long)h);
    return q1(w, sql) == applied ? 0 : -1;
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

/* tokenomics-v3 P2 — one CROSS-DOMAIN envelope carrying a conserving
 * native move: a SYSTEM leg that SETs the (non-supply) epoch_state
 * bookkeeping row to `accum_new`, and a CORE leg with TWO effects, the
 * transparent row 0x..01 SET to `utxo_new` and supply selector 3
 * (reward_pool) SET to `pool_new` — the fee → pool hop (P2-3) as a
 * scripted pair. Two DomainUpdates; the value moves inside CORE. */
static int env_cross_fee_to_pool(v2x_env_t *env, uint64_t accum_new,
                                 uint64_t utxo_new, uint64_t pool_new) {
    uint8_t skey[8], sval[8];
    v2x_put64(skey, 0);
    v2x_put64(sval, accum_new);
    uint8_t sres[256];
    size_t srl = 0;
    if (v2x_eff1(sres, sizeof(sres), V2X_OP_EPOCH, DNA_EFFECT_SET,
                 DNA_EFFECT_PRE_EXISTS, skey, 8, sval, 8, &srl) != 0)
        return -1;
    uint8_t ukey[64] = { 0 }, uval[8], pkey[1] = { 3 }, pval[8];
    ukey[63] = 0x01;
    v2x_put64(uval, utxo_new);
    v2x_put64(pval, pool_new);
    dna_effect_in_t effs[2];
    memset(effs, 0, sizeof(effs));
    effs[0].hdr.op_id = V2X_OP_UTXO;
    effs[0].hdr.effect_kind = DNA_EFFECT_SET;
    effs[0].hdr.precond_tag = DNA_EFFECT_PRE_EXISTS;
    effs[0].hdr.key_len = 64;
    effs[0].hdr.value_len = 8;
    effs[0].key = ukey;
    effs[0].value = uval;
    effs[1].hdr.op_id = V2X_OP_SUPPLY;
    effs[1].hdr.effect_kind = DNA_EFFECT_SET;
    effs[1].hdr.precond_tag = DNA_EFFECT_PRE_EXISTS;
    effs[1].hdr.key_len = 1;
    effs[1].hdr.value_len = 8;
    effs[1].key = pkey;
    effs[1].value = pval;
    uint8_t cres[512];
    size_t crl = 0;
    if (v2x_effres(cres, sizeof(cres), effs, 2, &crl) != 0) return -1;
    uint8_t scall[400], ccall[700];
    uint32_t scl = v2x_script_build(scall, sizeof(scall), NULL, 0,
                                    sres, srl);
    uint32_t ccl = v2x_script_build(ccall, sizeof(ccall), NULL, 0,
                                    cres, crl);
    if (!scl || !ccl) return -1;
    v2x_leg_t legs[2] = {
        { 0, 1, scall, scl, 4, 2048 },
        { 1, 1, ccall, ccl, 4, 2048 }
    };
    return v2x_env_build(env, legs, 2);
}

int main(void) {
    /* This file pins TOUCH ISOLATION ("SYSTEM advanced while untouched",
     * untouched-domain guards, per-block head heights). tokenomics-v3 P2
     * deleted the per-block mint, so every chain is quiet — the O15J
     * `v2x_inflation_off` switch this file used to set is gone. */
    fixture_t fx;
    CHECK(fx_open(&fx) == 0, "fixture"); OK();
    CHECK(v2x_table_init(fx.w) == 0, "scripted table"); OK();

    /* ── 1. genesis + cycle proof ───────────────────────────────────── */
    /* O14: seed the committed validator authority BEFORE capturing the
     * payload roots — the validator/vset legs are part of the SYSTEM
     * payload root, so seeding after the capture would move the root out
     * from under the cycle proof below. tokenomics-v3 P4: the authority
     * is the genesis committee a version-3 genesis always has
     * (v2x_seed_rows — the document's seven validators, their supply,
     * snapshots 0 and E). */
    CHECK(v2x_seed_rows(fx.w, 0) == 0, "seed authority"); OK();
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

    /* ── the cometbft genesis's own refusals ──────────────────────────
     * tokenomics-v3 P4 deleted the version-2 engine genesis
     * (nodus_witness_v2_genesis / _ex) this section used to drive; what
     * it pinned there is pinned here on the ONE genesis a chain can
     * have, nodus_witness_v2_genesis_cmt (nodus_witness_v2_apply.c).
     * Each refusal runs inside the engine's own transaction and rolls
     * back, so the successful genesis below is unaffected. The
     * version-2 entry's epoch argument and caller-asserted genesis id
     * have no counterpart — the cometbft genesis takes neither. */
    uint8_t vsh0[DNA_VSET_HASH_LEN], groot[64];
    uint8_t gman[8192];
    size_t gman_len = 0;
    CHECK(v2x_seed_vset_hash(fx.w, vsh0) == 0, "committed epoch-0 set");
    /* a genesis with NO manifest has no committed source binding */
    CHECK(nodus_witness_v2_genesis_cmt(fx.w, vsh0, NULL, 0, groot) == -1,
          "no-manifest genesis accepted"); OK();
    CHECK(v2x_seed_manifest(fx.w, gman, sizeof(gman), &gman_len) == 0,
          "genesis manifest");
    /* O14 review R1-F2, on the cometbft genesis: `vset_hash` is an
     * ASSERTION that must EQUAL the committed epoch-0 authority; a
     * foreign set rejects. */
    {
        uint8_t foreign[64];
        memset(foreign, 0x5C, sizeof(foreign));
        CHECK(nodus_witness_v2_genesis_cmt(fx.w, foreign, gman, gman_len,
                                           groot) == -1,
              "genesis bound a foreign validator_set_hash"); OK();
    }
    CHECK(v2x_seed_genesis(fx.w, fx.chain_id16, 0, gman, gman_len, NULL)
              == 0, "genesis");
    OK();
    /* NOT idempotent, by design (nodus_witness_v2_apply.h, the cometbft
     * genesis): a database that already carries a committed genesis
     * manifest refuses ANY second genesis — the committed one, a
     * DIVERGENT one, or none at all — where the version-2 entry's
     * idempotency probe accepted the committed one. A restarting node
     * verifies its genesis through InitChain; it never re-applies it.
     * HONEST LABEL (P4 fix round): nodus_witness_v2_genesis_cmt does NOT
     * compare a presented manifest with the committed one at all — it
     * refuses on the existence of ANY committed genesis manifest
     * ("already carries a committed genesis manifest"). So the DIVERGENT
     * case below proves only that a second genesis is refused whatever
     * its bytes; the version-2 entry's byte-for-byte divergence check
     * (O15A) has no counterpart, because nothing re-presents a manifest
     * to an existing genesis any more. */
    {
        static const uint8_t other_manifest[] =
            "this is definitively not the committed genesis manifest";
        CHECK(nodus_witness_v2_genesis_cmt(fx.w, vsh0, gman, gman_len,
                                           groot) == -1,
              "a second cometbft genesis (the committed manifest) was "
              "accepted"); OK();
        CHECK(nodus_witness_v2_genesis_cmt(fx.w, vsh0, other_manifest,
                                           sizeof(other_manifest),
                                           groot) == -1,
              "a DIVERGENT genesis manifest was accepted"); OK();
        CHECK(nodus_witness_v2_genesis_cmt(fx.w, vsh0, NULL, 0, groot)
                  == -1,
              "a no-manifest genesis must be refused even once genesis "
              "is already committed"); OK();
    }

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
        /* A version-3 chain writes NO height-0 block row (D-19 rev 6):
         * the genesis roots it commits are the activation heads, which
         * nodus_witness_v2_committed_global_root recomposes when no
         * block row exists, and the global root the genesis returned is
         * the stored document's app_hash. Both must equal an independent
         * full recomputation. */
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_blocks") == 0,
              "a version-3 genesis wrote a block row"); OK();
        uint8_t stored_g[64];
        CHECK(nodus_witness_v2_committed_global_root(fx.w, stored_g) == 0,
              "committed genesis root");
        uint8_t re_d[64], re_g[64];
        CHECK(nodus_witness_global_root_v2(fx.w, re_g, re_d, NULL, NULL)
                  == 0, "recompute");
        nodus_v2_gen_config_t *doc = calloc(1, sizeof(*doc));
        nodus_v2_gen_alloc_t *doc_allocs = NULL;
        CHECK(doc != NULL, "doc alloc");
        CHECK(nodus_witness_v2_gen_stored_doc(fx.w, doc, &doc_allocs) == 0,
              "stored genesis document");
        int app_ok = memcmp(doc->app_hash, re_g, 64) == 0;
        free(doc_allocs);
        free(doc);
        CHECK(memcmp(stored_g, re_g, 64) == 0 && app_ok,
              "genesis roots != recomputation"); OK();
    }

    /* an INDEPENDENT second fixture lands on byte-identical roots */
    {
        fixture_t fx2;
        CHECK(fx_open(&fx2) == 0, "fx2");
        CHECK(v2x_table_init(fx2.w) == 0, "table2");
        CHECK(v2x_seed_genesis(fx2.w, fx2.chain_id16, 0, NULL, 0, NULL)
                  == 0, "genesis2");
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
    CHECK(v2x_cmt_apply_ok(fx.w, &b1) == 0, "block 1"); OK();
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

    /* replay matrix — THE COMETBFT LANE. Consensus decides the height
     * and hands the ledger each decided block once, so this lane has no
     * idempotent replay path (the legacy lane's rc 1 required an
     * asserted expect_block_id, which this lane refuses) and no
     * block-level verdict: every linkage anomaly below — the committed
     * height again, a gap, height 0, an identity assertion, a reused
     * block hash, a lying epoch — is this node being handed a block it
     * cannot place, i.e. a node FAULT (NODUS_V2_INTERNAL_FAULT, the
     * wrapper's fold in nodus_witness_v2_apply_block), and none of them
     * may write a byte (v2x_cmt_fault: whole-database digest). The
     * legacy lane's DISTINCT classes (NOT_YET_LINKABLE vs
     * CONSENSUS_INVALID) are not observable here — they fold into the
     * one FAULT — and the classifier functions are pinned directly
     * below instead. */
    uint8_t dg[64], dg2[64];
    CHECK(v2x_db_digest(fx.w, dg) == 0, "digest");
    /* The hash block 1 was committed under — consensus's, stored
     * verbatim (the ledger derives no identity in this lane). */
    uint8_t b1_hash[64];
    memcpy(b1_hash, b1.cmt.block_hash, 64);
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_blocks WHERE "
                   "global_height = 1") == 1 &&
          memcmp(b1.out_block_id, b1_hash, 64) == 0,
          "block 1 was not committed under the block hash it carried");
    OK();

    /* The committed height again: no fast path, a FAULT, no write. */
    nodus_v2_block_t rb;
    mk_block(&rb, 1, &v1, 1);
    CHECK(v2x_cmt_fault_why(fx.w, &rb, V2X_VERDICT, "at or below") == 0,
          "identical replay not idempotent"); OK();

    /* An identity ASSERTION (the legacy follower channel) is refused
     * outright in this lane — the identity is the caller's input, not a
     * derivation to assert (nodus_witness_v2_apply.c, the cmt.on entry
     * gate). */
    uint8_t bad_id[64];
    memcpy(bad_id, b1_hash, 64);
    bad_id[0] ^= 1;                            /* same height, diff id  */
    mk_block(&rb, 1, &v1, 1);
    rb.expect_block_id = bad_id;
    CHECK(v2x_cmt_fault_why(fx.w, &rb, V2X_FAULT,
                            "identity assertions") == 0,
          "conflicting height accepted"); OK();

    static v2x_env_t ex;
    CHECK(env_core_utxo_create(&ex, 0x0f, 5) == 0, "envx");
    nodus_v2_envelope_t vx = { ex.bytes, ex.len };
    nodus_v2_block_t bx;
    /* a height GAP: predecessors absent on this node */
    mk_block(&bx, 3, &vx, 1);                  /* gap                    */
    /* the body still CLASSIFIES it a DEFERRAL (O15A: predecessor state
     * absent, nothing judged) before the fold makes it a FAULT */
    CHECK(v2x_cmt_fault_why(fx.w, &bx, V2X_DEFER, "AHEAD") == 0,
          "height gap must be NOT_YET_LINKABLE, not a verdict");
    OK();

    /* ── O15A §9: the LINKAGE MATRIX, in the cometbft lane ───────────
     * Each shape a FAULT that writes nothing (asserted per case by
     * v2x_cmt_fault, and once more over the whole matrix). */
    {
        uint8_t lg[64], lg2[64];
        CHECK(v2x_db_digest(fx.w, lg) == 0, "linkage digest"); OK();

        mk_block(&bx, 1000000, &vx, 1);
        CHECK(v2x_cmt_fault_why(fx.w, &bx, V2X_DEFER, "AHEAD") == 0,
              "large height gap must be NOT_YET_LINKABLE"); OK();

        /* Height 0: the chain's genesis is its document, never a block
         * this entry applies — a VERDICT in the body, tested FIRST. */
        mk_block(&bx, 0, &vx, 1);
        CHECK(v2x_cmt_fault_why(fx.w, &bx, V2X_VERDICT,
                                "height 0 cannot be applied") == 0,
              "height 0 through apply_block must be a verdict");
        OK();

        /* STALE — at or below the head: evaluable now, a VERDICT, never
         * the deferral class. */
        mk_block(&bx, 1, &vx, 1);
        CHECK(v2x_cmt_fault_why(fx.w, &bx, V2X_VERDICT, "at or below")
                  == 0,
              "stale height must stay a verdict, not NOT_YET_LINKABLE");
        OK();

        /* None of the above may touch a single byte of state. */
        CHECK(v2x_db_digest(fx.w, lg2) == 0 && memcmp(lg, lg2, 64) == 0,
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
    /* an asserted PARENT is an identity assertion too: refused */
    mk_block(&bx, 2, &vx, 1);
    uint8_t wrong_prev[64];
    memset(wrong_prev, 0x5A, 64);              /* wrong prev             */
    bx.expect_prev_block_id = wrong_prev;
    CHECK(v2x_cmt_fault_why(fx.w, &bx, V2X_FAULT,
                            "identity assertions") == 0,
          "wrong prev accepted"); OK();
    /* A block at height 2 carrying block 1's HASH: the one identity this
     * lane stores is consensus's, and phase 13's duplicate-id probe
     * refuses a hash already committed at another height. */
    mk_block(&bx, 2, &vx, 1);
    CHECK(v2x_cmt_fault_with_hash_why(fx.w, &bx, b1_hash, V2X_VERDICT,
                                      "committed at ANOTHER height") == 0,
          "reused BlockID accepted"); OK();
    /* wrong DECLARED epoch: the derivation is the authority */
    mk_block(&bx, 2, &vx, 1);
    bx.epoch = 1;                              /* height 2 is epoch 0    */
    CHECK(v2x_cmt_fault_why(fx.w, &bx, V2X_VERDICT, "declares epoch")
              == 0,
          "wrong block epoch accepted"); OK();
    CHECK(v2x_db_digest(fx.w, dg2) == 0 && memcmp(dg, dg2, 64) == 0,
          "rejected blocks wrote state"); OK();

    /* block 2: SYSTEM-only */
    static v2x_env_t e2;
    CHECK(env_sys_cc(&e2, 999991, 5) == 0, "env2");
    nodus_v2_envelope_t v2 = { e2.bytes, e2.len };
    nodus_v2_block_t b2;
    mk_block(&b2, 2, &v2, 1);
    CHECK(v2x_cmt_apply_ok(fx.w, &b2) == 0, "block 2"); OK();
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
    CHECK(v2x_cmt_apply_ok(fx.w, &b3) == 0, "block 3"); OK();
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

    /* The three shapes below are BLOCK-level checks (phase 9's declared
     * no-op, phase 8's untouched-domain guard, phase 13's expected-root
     * compare). The cometbft lane runs them after the item loop, over
     * the block as a whole, and a decided block is never refused — so
     * each is a node FAULT here (the item applied inside the block's
     * transaction and the host rolled the whole block back), where the
     * legacy lane returned a verdict. Nothing may be written either
     * way. */
    CHECK(v2x_db_digest(fx.w, dg) == 0, "digest");
    /* declared no-op (empty typed result, no fake updates) */
    static v2x_env_t enoop;
    CHECK(env_core_empty(&enoop) == 0, "enoop");
    nodus_v2_envelope_t vnoop = { enoop.bytes, enoop.len };
    nodus_v2_block_t b4;
    mk_block(&b4, 4, &vnoop, 1);
    CHECK(v2x_cmt_fault_why(fx.w, &b4, V2X_VERDICT, "DECLARED no-op")
              == 0,
          "declared no-op produced an update"); OK();
    /* undeclared mutation (adapter domain-escape caught by the
     * untouched-domain guard) */
    rogue_table_arm(fx.w);
    static v2x_env_t erogue;
    CHECK(env_sys_cc(&erogue, 999992, 5) == 0, "erogue");
    nodus_v2_envelope_t vrogue = { erogue.bytes, erogue.len };
    mk_block(&b4, 4, &vrogue, 1);
    CHECK(v2x_cmt_fault_why(fx.w, &b4, V2X_VERDICT,
                            "UNTOUCHED-DOMAIN GUARD") == 0,
          "undeclared CORE mutation accepted"); OK();
    rogue_table_disarm(fx.w);
    /* wrong expected root */
    static v2x_env_t eok4;
    CHECK(env_core_utxo_create(&eok4, 0x42, 5) == 0, "eok4");
    nodus_v2_envelope_t vok4 = { eok4.bytes, eok4.len };
    mk_block(&b4, 4, &vok4, 1);
    uint8_t bad_root[64];
    memset(bad_root, 0xDD, 64);
    b4.expect_global_root = bad_root;
    CHECK(v2x_cmt_fault_why(fx.w, &b4, V2X_VERDICT,
                            "global_root mismatch") == 0,
          "wrong expected root accepted"); OK();
    CHECK(v2x_db_digest(fx.w, dg2) == 0 && memcmp(dg, dg2, 64) == 0,
          "rejected block 4 candidates wrote state"); OK();

    /* ── 4. cross-domain atomicity ──────────────────────────────────── */
    static v2x_env_t ecross;
    CHECK(env_cross_cc_utxo(&ecross, 999992, 0x50, 30) == 0, "ecross");
    nodus_v2_envelope_t vcross = { ecross.bytes, ecross.len };
    nodus_v2_block_t b4c;
    mk_block(&b4c, 4, &vcross, 1);
    CHECK(v2x_cmt_apply_ok(fx.w, &b4c) == 0, "cross block");
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

    /* A fault BETWEEN the two legs of one cross-domain envelope →
     * NEITHER half survives. The legacy lane proved this with its
     * phase-order points (after the SYSTEM phase, after the CORE batch),
     * which the cometbft lane does not have — it executes the block in
     * item order, one SAVEPOINT per item. The lane's own half-envelope
     * point is F38 (V2AP_FAIL_AFTER_LEG_APPLY, nodus_witness_v2_apply.h):
     * it fires after the named leg has fully applied and before the
     * next one starts, the item is refused (EXEC) and its SAVEPOINT
     * carries both halves away — the ledger is byte-identical. Leg 0 is
     * the SYSTEM record leg, leg 1 the CORE leg. Each refusal commits
     * its (itemless) block and consumes a height. */
    uint64_t h = 5;
    uint32_t code = 0;
    static v2x_env_t ecross2;
    CHECK(env_cross_cc_utxo(&ecross2, 999993, 0x51, 40) == 0, "ecross2");
    nodus_v2_envelope_t vcross2 = { ecross2.bytes, ecross2.len };
    nodus_v2_block_t b5;
    mk_block(&b5, h++, &vcross2, 1);
    b5.fail_at = V2AP_FAIL_AFTER_LEG_APPLY;
    b5.fail_env_index = 0;
    b5.fail_leg_index = 0;
    CHECK(v2x_cmt_refused(fx.w, &b5, 0, &code) == 0 &&
          code == NODUS_V2_TX_ERR_EXEC,
          "SYSTEM half survived"); OK();
    mk_block(&b5, h++, &vcross2, 1);
    b5.fail_at = V2AP_FAIL_AFTER_LEG_APPLY;
    b5.fail_env_index = 0;
    b5.fail_leg_index = 1;
    CHECK(v2x_cmt_refused(fx.w, &b5, 0, &code) == 0 &&
          code == NODUS_V2_TX_ERR_EXEC,
          "CORE half survived"); OK();

    /* ── 5. fault injection (rich block), then a restart ─────────────
     * Every BLOCK-level point the cometbft lane reaches — the ones on
     * its own path from the (host's) transaction to the block row:
     * after BEGIN, the post-stage supply gate, domain roots, updates,
     * heads, history, the tx index, the envelope and claim bytes, the
     * block row, and before the (host's) commit. Each is a node FAULT
     * and the host's ROLLBACK leaves the WHOLE database byte-identical.
     * The legacy lane's phase-order points (after SYSTEM, after CROSS,
     * after a domain batch, after the UTXO phase), its whole-batch
     * pre-BEGIN points (F26 after the batch reserve, F27 after an
     * envelope's exec), its engine-owned COMMIT (F14) and its
     * post-commit crash window (F15, rc 2) have NO cometbft-lane
     * counterpart: those stages do not exist there (the host owns the
     * commit). The per-ITEM counterpart of F27 follows the loop. */
    static v2x_env_t er1, er2, er3;
    CHECK(env_sys_cc(&er1, 999994, 5) == 0, "er1");
    CHECK(env_cross_cc_utxo(&er2, 999995, 0x62, 11) == 0, "er2");
    CHECK(env_core_utxo_create(&er3, 0x63, 12) == 0, "er3");
    nodus_v2_envelope_t rich[3] = {
        { er1.bytes, er1.len }, { er2.bytes, er2.len },
        { er3.bytes, er3.len }
    };
    {
        static const nodus_v2_apply_fail_t cmt_pts[] = {
            V2AP_FAIL_AFTER_BEGIN,        V2AP_FAIL_AFTER_SUPPLY_MUT,
            V2AP_FAIL_AFTER_DOMAIN_ROOTS, V2AP_FAIL_AFTER_UPDATES,
            V2AP_FAIL_AFTER_HEADS,        V2AP_FAIL_AFTER_HISTORY,
            V2AP_FAIL_AFTER_TX_INDEX,     /* F48 retired: P4 fix round */
            V2AP_FAIL_AFTER_CLAIM_BYTES,  V2AP_FAIL_AFTER_BLOCK_META,
            V2AP_FAIL_BEFORE_COMMIT
        };
        for (size_t f = 0; f < sizeof(cmt_pts) / sizeof(cmt_pts[0]); f++) {
            nodus_v2_block_t bf;
            mk_block(&bf, h, rich, 3);
            bf.fail_at = cmt_pts[f];
            CHECK(v2x_cmt_fault_why(fx.w, &bf, V2X_VERDICT,
                                    "fault-injection point") == 0,
                  "fault point did not fail");
        }
    }
    OK();
    /* The per-ITEM counterpart of F27: a fault point INSIDE one item's
     * execution (F31, after the native exec hook returned) refuses THAT
     * item — its effects and identity rows go with its SAVEPOINT — while
     * the block's other items commit around it. */
    {
        nodus_v2_block_t bf;
        mk_block(&bf, h, rich, 3);
        bf.fail_at = V2AP_FAIL_AFTER_EXEC_HOOK;
        bf.fail_env_index = 1;
        CHECK(v2x_cmt_apply(fx.w, &bf) == 0 &&
              bf.cmt.results[0].code == NODUS_V2_TX_OK &&
              bf.cmt.results[1].code == NODUS_V2_TX_ERR_EXEC &&
              bf.cmt.results[2].code == NODUS_V2_TX_OK, "F27 rc");
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM chain_config_history WHERE "
                       "param_id = 2 AND effective_block = 999994") == 1 &&
              q1(fx.w, "SELECT COUNT(*) FROM utxo_set WHERE "
                       "nullifier=CAST(zeroblob(63)||x'63' AS BLOB)") == 1,
              "the refused item's siblings did not commit"); OK();
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM chain_config_history WHERE "
                       "param_id = 2 AND effective_block = 999995") == 0 &&
              q1(fx.w, "SELECT COUNT(*) FROM utxo_set WHERE "
                       "nullifier=CAST(zeroblob(63)||x'62' AS BLOB)") == 0 &&
              q1(fx.w, "SELECT COUNT(*) FROM v2_tx_index WHERE "
                       "global_height = (SELECT MAX(global_height) FROM "
                       "v2_blocks)") == 2,
              "F27 leaked state"); OK();
    }
    /* restart: the committed state survives a reopen byte-identically */
    uint8_t dg_committed[64];
    CHECK(v2x_db_digest(fx.w, dg_committed) == 0, "digest");
    CHECK(fx_reopen(&fx) == 0, "reopen after F15");
    CHECK(v2x_db_digest(fx.w, dg2) == 0 &&
          memcmp(dg_committed, dg2, 64) == 0,
          "restart lost committed state"); OK();
    /* After the restart: the committed height again is a FAULT that
     * writes nothing (the legacy lane's idempotent rc 1 has no
     * counterpart — see the replay matrix above), and the item that
     * was REFUSED left no identity behind: resubmitted at the next
     * height it applies, where an applied sibling would be a REPLAY. */
    nodus_v2_block_t b5r;
    mk_block(&b5r, h, rich, 3);
    CHECK(v2x_cmt_fault_why(fx.w, &b5r, V2X_VERDICT, "at or below") == 0,
          "post-crash replay applied twice"); OK();
    h++;
    {
        nodus_v2_envelope_t again[2] = {
            { er2.bytes, er2.len }, { er1.bytes, er1.len }
        };
        mk_block(&b5r, h++, again, 2);
        CHECK(v2x_cmt_apply(fx.w, &b5r) == 0 &&
              b5r.cmt.results[0].code == NODUS_V2_TX_OK &&
              b5r.cmt.results[1].code == NODUS_V2_TX_ERR_REPLAY,
              "restart served a different identity"); OK();
        /* per-item effects (P4 fix round): the REPLAY-refused copy wrote
         * no second identity row — only the resubmitted item is indexed
         * at this height (fee 0, no funding input: see the quota block) */
        CHECK(idx_rows_are(fx.w, b5r.global_height, 1) == 0,
              "the REPLAY-refused item left an identity row"); OK();
    }

    /* ── 6. resource limits ─────────────────────────────────────────── */
    {   /* R3 W4-C delta 2 (operator "kaldır" 2026-09-18;
         * atlas-dec-5b7568512b95e6d2e671c4eaad2c1879 rev 1): the global
         * tx-count cap (chain-config MAX_TXS_PER_BLOCK, the retired
         * parameter) is DELETED from the engine (apply.c's "global
         * tx-count cap" block is gone). 11 envelopes — one MORE than the
         * old hard cap of 10 — now APPLY: RED on delta 1, which asserted
         * `== -1` ("global tx cap ignored") for this exact same block
         * shape. This block COMMITS at height 6, becoming the first
         * real height-6 row in this fixture (delta 1's own mixed-leg
         * test below moves to height 7 to make room).
         *
         * R3 W4-C delta 3 fix: the default ceiling (200000,
         * v2x_env_build) is what actually binds 11 envelopes — NOT a
         * count. dna_meter_reserve takes the FULL declared
         * res_max_total_units from NODUS_V2_GLOBAL_UNIT_BUDGET at
         * reserve time: at 1000000 the 6th reservation faulted with
         * DNA_METER_ERR_GLOBAL_BUDGET; at the trial-B 2097152 (operator
         * 2026-09-24) the 11th still does (11 x 200000 = 2200000) — the
         * UNIT BUDGET binding, not the retired count cap, and the wrong
         * thing for this case to prove. Each envelope here uses
         * env_core_utxo_create_ceiling with a ceiling DERIVED from the
         * macro instead: budget / 12, so 11 of them take 11/12 of the
         * budget (comfortably under it, whatever its value) while the
         * ceiling stays far above the ~2236-unit floor this leg's own
         * static_units cost (see the helper's comment) — both checked
         * below, so a future budget small enough to break either fails
         * HERE, named, not as an unexplained apply refusal. */
        const uint64_t ceil11 = (uint64_t)NODUS_V2_GLOBAL_UNIT_BUDGET / 12u;
        CHECK(ceil11 >= 2236u * 4u &&
              11u * ceil11 < (uint64_t)NODUS_V2_GLOBAL_UNIT_BUDGET,
              "the derived per-envelope ceiling must clear the leg's "
              "static floor and fit 11 times under the global budget");
        OK();
        static v2x_env_t many[11];
        nodus_v2_envelope_t vm[11];
        for (int i = 0; i < 11; i++) {
            CHECK(env_core_utxo_create_ceiling(&many[i],
                      (uint8_t)(0x70 + i), 1, ceil11)
                      == 0, "env many");
            vm[i].env_bytes = many[i].bytes;
            vm[i].env_len = many[i].len;
        }
        nodus_v2_block_t bm;
        mk_block(&bm, h++, vm, 11);
        CHECK(v2x_cmt_apply_ok(fx.w, &bm) == 0,
              "R3 W4-C delta 2: 11 envelopes did not apply — the retired "
              "chain-config item cap must no longer bind them (RED on "
              "delta 1: -1, \"global tx cap ignored\")"); OK();
    }
    {   /* the engine's OWN surviving envelope-count ceiling
         * (`NODUS_V2_ENV_BATCH_MAX`, a derived MEMORY bound — never a
         * consensus parameter, R3 W4-C delta 2), proven with a STUB
         * array: `v2_apply_block_body`'s SECOND check (apply.c, right
         * after the NULL-envs FAULT and BEFORE schema/epoch/replay)
         * rejects on `blk->n_envs` ALONE, before decoding envelope 0 —
         * env.c's own ARG gate (`nodus_witness_v2_env_preflight_
         * reserve_batch`, :59/:305) is the identical shape one layer
         * down. Building NODUS_V2_ENV_BATCH_MAX + 1 (thousands) of REAL
         * distinct envelopes to reach a VERDICT that fires before any of
         * them are read would prove nothing more than this one real,
         * valid, non-NULL entry does — it clears the NULL-envs FAULT and
         * is never actually indexed. */
        static v2x_env_t stub_env;
        nodus_v2_envelope_t stub[1];
        nodus_v2_block_t bx;
        CHECK(env_core_utxo_create(&stub_env, 0x7B, 1) == 0, "stub env");
        stub[0].env_bytes = stub_env.bytes;
        stub[0].env_len   = stub_env.len;
        /* cometbft lane: a count the engine cannot hold is refused on
         * the count alone, and — a decided block is never refused — as a
         * node FAULT that writes nothing (ProcessProposal never lets an
         * honest network decide such a block). */
        mk_block(&bx, h, stub, NODUS_V2_ENV_BATCH_MAX + 1);
        CHECK(v2x_cmt_fault_why(fx.w, &bx, V2X_VERDICT,
                                "exceeds the engine bound") == 0,
              "NODUS_V2_ENV_BATCH_MAX + 1 declared envelopes accepted — "
              "the engine's own memory-ceiling VERDICT must reject on "
              "the count alone"); OK();
    }
    {   /* global UNIT budget: a reservation ceiling the block budget
         * cannot cover rejects at reserve — the item's CAPACITY code */
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
        mk_block(&bb, h++, &vb, 1);
        CHECK(v2x_cmt_refused(fx.w, &bb, 0, &code) == 0 &&
              code == NODUS_V2_TX_ERR_CAPACITY,
              "global unit budget ignored"); OK();
        CHECK(idx_rows_are(fx.w, bb.global_height, 0) == 0,
              "the over-global-budget item left an identity row"); OK();
    }
    {   /* per-domain quota + unit budget via a CONSISTENT
         * fixture-written CORE manifest.
         *
         * The rewrite is an out-of-band SYSTEM mutation (the registry is
         * a SYSTEM root leg): a block that does not TOUCH SYSTEM would
         * die at phase 8's untouched-domain guard — a block-level check,
         * a node FAULT in the cometbft lane, which would mask the quota.
         * So each quota block LEADS with a SYSTEM chain-config item
         * (fresh keys 999980/999981), and the refusal under test is the
         * CORE item's own per-item CAPACITY code. The manifest restore
         * at the end is absorbed by 6b's block, which touches SYSTEM
         * too. */
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

        static v2x_env_t eqs1, eq1, eq2;
        CHECK(env_sys_cc(&eqs1, 999980, 5) == 0, "eqs1");
        CHECK(env_core_utxo_create(&eq1, 0x81, 1) == 0, "eq1");
        CHECK(env_core_utxo_create(&eq2, 0x82, 1) == 0, "eq2");
        nodus_v2_envelope_t vq[3] = {
            { eqs1.bytes, eqs1.len },
            { eq1.bytes, eq1.len }, { eq2.bytes, eq2.len }
        };
        nodus_v2_block_t bq;
        mk_block(&bq, h++, vq, 3);
        CHECK(v2x_cmt_apply(fx.w, &bq) == 0 &&
              bq.cmt.results[0].code == NODUS_V2_TX_OK &&
              bq.cmt.results[1].code == NODUS_V2_TX_OK &&
              bq.cmt.results[2].code == NODUS_V2_TX_ERR_CAPACITY,
              "per-domain tx quota ignored"); OK();
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM utxo_set WHERE "
                       "nullifier=CAST(zeroblob(63)||x'81' AS BLOB)") == 1 &&
              q1(fx.w, "SELECT COUNT(*) FROM utxo_set WHERE "
                       "nullifier=CAST(zeroblob(63)||x'82' AS BLOB)") == 0,
              "resource rejections leaked state"); OK();
        /* per-item effects (P4 fix round): the refused item left no
         * identity row — exactly the two APPLIED items are indexed. These
         * script-runtime envelopes declare fee 0 and spend no funding
         * input (v2x_env_build_ex), so there is no fee debit or funding
         * spend to check here; those legs are pinned at the native sites
         * (test_v2_native C6 and the token duplicate). */
        CHECK(idx_rows_are(fx.w, bq.global_height, 2) == 0,
              "the quota-refused item left an identity row"); OK();

        /* per-domain UNIT budget: quota_verify_cost is the committed
         * per-block unit budget — 5 units cannot cover any real leg's
         * static reservation */
        qman.quota_tx_per_block = 0;
        qman.quota_verify_cost = 5;
        WRITE_CORE_MAN(&qman);
        static v2x_env_t eqs2, eqc;
        CHECK(env_sys_cc(&eqs2, 999981, 5) == 0, "eqs2");
        CHECK(env_core_utxo_create(&eqc, 0x83, 1) == 0, "eqc");
        nodus_v2_envelope_t vqc[2] = {
            { eqs2.bytes, eqs2.len }, { eqc.bytes, eqc.len }
        };
        mk_block(&bq, h++, vqc, 2);
        CHECK(v2x_cmt_apply(fx.w, &bq) == 0 &&
              bq.cmt.results[0].code == NODUS_V2_TX_OK &&
              bq.cmt.results[1].code == NODUS_V2_TX_ERR_CAPACITY,
              "per-domain unit budget ignored"); OK();
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM utxo_set WHERE "
                       "nullifier=CAST(zeroblob(63)||x'83' AS BLOB)") == 0,
              "the over-budget item leaked state"); OK();
        CHECK(idx_rows_are(fx.w, bq.global_height, 1) == 0,
              "the over-budget item left an identity row"); OK();
        /* restore the genesis manifest (consistent again) */
        WRITE_CORE_MAN(&core_man);
#undef WRITE_CORE_MAN
    }

    /* ── 6b. R3 W4 package C: per-item auth verdicts ──────────────────
     * The cometbft lane authorizes each item into ONE reusable
     * DNA_ENV_MAX_LEGS-slot buffer, indexed relative to that item
     * (nodus_witness_v2_apply.c, the Comet item loop; the legacy lane's
     * whole-batch `auth_off` table is deleted with that lane). A block
     * mixing a TWO-leg envelope with ONE-leg envelopes stresses exactly
     * that reuse: a later item reading a slot the earlier two-leg item
     * left behind would get an empty/garbage verdict (`n_signers < 1`, a
     * FAULT in `exec_one_env`) or a MISAUTHORIZED leg. `env0` (SYSTEM+
     * CORE cross-domain, 2 legs) followed by `env1`/`env2` (CORE-only, 1
     * leg each) applying cleanly, with every one of the three
     * envelopes' derived identities committed, is the proof: every leg
     * found ITS OWN verdict, not a neighbour's. (This block also touches
     * SYSTEM, which absorbs the registry restore just above.) */
    {
        static v2x_env_t emix_cross, emix_a, emix_b;
        nodus_v2_envelope_t vmix[3];
        nodus_v2_block_t bmix;
        uint64_t h_sys6 = 0, h_core6 = 0;

        /* ORCHESTRATOR (W4-C ORC-1): the writer's first draft reused
         * effblock 999994 — already committed by er1 at :912 — so the
         * SYSTEM leg's CREATE/ABSENT precondition refused the block
         * (status 7) and the section was RED for the wrong reason. Every
         * key here is fresh (grep: 999996 / 0xa1-0xa3 unused elsewhere). */
        CHECK(env_cross_cc_utxo(&emix_cross, 999996, 0xa1, 7) == 0,
              "emix_cross (2 legs: SYSTEM+CORE)");
        CHECK(env_core_utxo_create(&emix_a, 0xa2, 1) == 0,
              "emix_a (1 leg: CORE)");
        CHECK(env_core_utxo_create(&emix_b, 0xa3, 1) == 0,
              "emix_b (1 leg: CORE)");
        vmix[0].env_bytes = emix_cross.bytes;
        vmix[0].env_len   = emix_cross.len;
        vmix[1].env_bytes = emix_a.bytes;
        vmix[1].env_len   = emix_a.len;
        vmix[2].env_bytes = emix_b.bytes;
        vmix[2].env_len   = emix_b.len;

        const uint64_t hmix = h++;
        char sqlmix[128];
        mk_block(&bmix, hmix, vmix, 3);
        CHECK(v2x_cmt_apply_ok(fx.w, &bmix) == 0,
              "mixed 2-leg + 1-leg + 1-leg block did not apply — a wrong "
              "auth_off entry would misauthorize or FAULT a later "
              "envelope's leg"); OK();
        CHECK(head_height(fx.w, 0, &h_sys6) == 0 &&
              head_height(fx.w, 1, &h_core6) == 0,
              "post-mix heads readable"); OK();
        snprintf(sqlmix, sizeof(sqlmix), "SELECT COUNT(*) FROM v2_tx_index "
                 "WHERE global_height=%llu", (unsigned long long)hmix);
        CHECK(q1(fx.w, sqlmix) == 3,
              "all three envelopes' identities committed — none lost to "
              "a misrouted auth verdict"); OK();
    }
    fx_close(&fx);

    /* ── 7. supply (official DNA numbers) ───────────────────────────── */
    /* O15J — this is the ONE section of this file that tests the
     * conservation equation ITSELF. The fixture arms a test-only bypass
     * on EVERY seeded genesis (v2x_seed_genesis, v2_genesis_fixture.h),
     * and from here to the end of the run this file asserts things about
     * the live invariant, so it is disarmed once here.
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

    /* The official numbers are the genesis rows of THIS chain (seeded
     * between v2x_seed_prepare and v2x_seed_genesis — the test's own
     * seven 10M validators, so the fixture adds no committee), and the
     * direct-SQL matrix below runs on them BEFORE the engine genesis. */
    fixture_t fs;
    CHECK(fx_open(&fs) == 0, "supply fixture"); OK();
    CHECK(v2x_table_init(fs.w) == 0, "scripted table (supply)");

    CHECK(run_sql(fs.w->db,
        "INSERT INTO supply_tracking (id, genesis_supply, total_burned, "
        "total_minted, current_supply, last_tx_hash, last_sequence) "
        "VALUES (1, 100000000000000000, 0, 0, 100000000000000000, "
        "x'00', 0)") == 0, "supply row"); OK();
    for (int i = 0; i < 7; i++) {
        /* P4 fix round: the destination fingerprint is WRITABLE-SHAPED
         * (128 lowercase hex, nodus_witness_v2_epoch_val_rec_ok) — it
         * was 'fpN', a row no real genesis can commit and the seeded
         * genesis's post-conditions now refuse. */
        char fpx[129];
        memset(fpx, 'a', 128);
        snprintf(fpx + 126, 3, "%02x", (unsigned)i);
        char sql[768];
        snprintf(sql, sizeof(sql),
            "INSERT INTO validators (pubkey_hash, pubkey, self_stake, "
            "total_delegated, commission_bps, status, active_since_block, "
            "unstake_destination_fp, unstake_destination_pubkey) "
            "VALUES (zeroblob(63)||x'%02x', zeroblob(2591)||x'%02x', "
            "1000000000000000, 0, 100, 0, 0, '%s', zeroblob(2592))",
            0xA0 + i, 0xB0 + i, fpx);
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
    /* tokenomics-v3 P2-2: the reward reserve's three hops are MOVES —
     * fee utxo → reward_pool (P2-3), pool → v2_reward_accrual (the
     * boundary distribution, P2-6), accrual → utxo (payday, P2-7) —
     * and the equation must hold after each. KILLED BY: a supply gate
     * that omits the pool term or the accrual term. */
    CHECK(run_sql(fs.w->db,
        "UPDATE utxo_set SET amount = amount - 3200 "
        "WHERE nullifier=CAST(zeroblob(63)||x'01' AS BLOB);"
        "UPDATE supply_tracking SET reward_pool = reward_pool + 3200")
        == 0, "fee to pool");
    CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "fee→pool broke"); OK();
    CHECK(run_sql(fs.w->db,
        "UPDATE supply_tracking SET reward_pool = reward_pool - 3200;"
        "INSERT INTO v2_reward_accrual (owner_fp, amount) "
        "VALUES (zeroblob(64), 3200)") == 0, "distribute");
    CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "pool→accrual broke");
    OK();
    CHECK(run_sql(fs.w->db,
        "DELETE FROM v2_reward_accrual;"
        "UPDATE utxo_set SET amount = amount + 3200 "
        "WHERE nullifier=CAST(zeroblob(63)||x'01' AS BLOB)") == 0, "payday");
    CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "accrual→utxo broke");
    OK();
    /* the RETIRED O15J term: a mint parked in epoch_state is no longer
     * backed by anything the gate counts (P2-4 deleted the mint and the
     * term with it) — it must violate. KILLED BY: a gate that still sums
     * epoch_state.epoch_pool_accum. */
    CHECK(run_sql(fs.w->db,
        "UPDATE supply_tracking SET total_minted = total_minted + 3200;"
        "INSERT INTO epoch_state (epoch_start_height, epoch_pool_accum, "
        "snapshot_hash) VALUES (0, 3200, zeroblob(64))") == 0, "old mint");
    CHECK(nodus_witness_v2_supply_check(fs.w) != 0,
          "an epoch_state-parked mint still conserved"); OK();
    CHECK(run_sql(fs.w->db,
        "UPDATE supply_tracking SET total_minted = total_minted - 3200")
        == 0, "undo old mint");
    CHECK(nodus_witness_v2_supply_check(fs.w) == 0,
          "epoch_state is no supply term"); OK();
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
        "UPDATE supply_tracking SET total_minted = 0") == 0, "restore");
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
    /* The engine genesis over these rows — its own supply gate must
     * pass on them — and the RESTART: v2x_seed_genesis ends by reopening
     * the database through the production open path, so the invariant
     * below is evaluated on the restarted chain. (A pre-genesis S16
     * database cannot be reopened through that path at all: its
     * post-open gate refuses S14 stores without a stored document —
     * nodus_witness.c, the chain-role gate.) */
    /* not a real genesis: the official-numbers carve-out is ONE spendable
     * 930M genesis UTXO, where the derivation's allocations hold none */
    v2x_seed_not_real(V2X_SEED_NOT_REAL_UTXOS);
    CHECK(v2x_seed_genesis(fs.w, fs.chain_id16, 0, NULL, 0, NULL) == 0,
          "supply-fixture genesis"); OK();
    /* O15J — the seeded genesis RE-ARMS the test-only bypass, so it
     * must be disarmed again here.
     *
     * CORRECTED after review R1: with the bypass live the assertions
     * below would FAIL, not become vacuous — the block would commit.
     * The disarm is still required; the hazard is simply a loud failure
     * rather than a silent pass. The silent-pass hazard belongs to the
     * positive assertions after this point. */
    nodus_witness_v2_supply_test_bypass(0);
    CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "restart broke"); OK();

    /* an engine block that BREAKS supply. The post-stage supply gate is
     * a BLOCK-level check (phase 7, after the item loop), so in the
     * cometbft lane the conjuring item applies inside the block's
     * transaction and the gate turns the whole block into a node FAULT
     * the host rolls back: nothing leaks (whole-database digest). */
    static v2x_env_t einf;
    CHECK(env_core_utxo_create(&einf, 0x90, 999) == 0, "einf");
    nodus_v2_envelope_t vinf = { einf.bytes, einf.len };
    nodus_v2_block_t sb;
    mk_block(&sb, 1, &vinf, 1);
    CHECK(v2x_cmt_fault_why(fs.w, &sb, V2X_VERDICT,
                            "POST-STAGE supply gate") == 0,
          "supply-breaking block accepted"); OK();

    /* ── 8. SUPPLY OWNERSHIP through TYPED cross-domain envelopes ───── */
    {
        /* (a) THE RETIRED MINT: total_minted (CORE, SUPPLY_SET absolute)
         * + epoch pool (SYSTEM, EPOCH_SET absolute) — the O15J shape,
         * which conserved while epoch_state was a supply term. Since
         * tokenomics-v3 P2-2/P2-4 nothing backs it: the supply gate
         * rejects the block and nothing leaks. KILLED BY: a gate that
         * still counts epoch_state.epoch_pool_accum. */
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
        /* the supply gate is block-level: a node FAULT in the cometbft
         * lane, rolled back by the host (whole-database digest) */
        mk_block(&mb, 1, &vmint, 1);
        CHECK(v2x_cmt_fault_why(fs.w, &mb, V2X_VERDICT,
                                "POST-STAGE supply gate") == 0,
              "an unbacked mint (the retired epoch-pool shape) accepted");
        CHECK(q1(fs.w, "SELECT total_minted FROM supply_tracking")
                  == minted, "nothing minted");
        OK();

        /* (b) FEE → POOL across a cross-domain envelope: SYSTEM leg (the
         * non-supply epoch_state row) + CORE leg (transparent row −500,
         * reward_pool +500) — two DomainUpdates, conserved. */
        uint64_t amt = q1(fs.w, "SELECT amount FROM utxo_set WHERE "
                                "nullifier=CAST(zeroblob(63)||x'01' AS BLOB)");
        uint64_t pool = q1(fs.w, "SELECT reward_pool FROM supply_tracking");
        static v2x_env_t efee;
        CHECK(env_cross_fee_to_pool(&efee, accum + 500, amt - 500,
                                    pool + 500) == 0, "efee");
        nodus_v2_envelope_t vfee = { efee.bytes, efee.len };
        mk_block(&mb, 1, &vfee, 1);
        CHECK(v2x_cmt_apply_ok(fs.w, &mb) == 0, "fee block");
        CHECK(q1(fs.w, "SELECT COUNT(*) FROM v2_domain_updates "
                       "WHERE global_height=1") == 2,
              "the move must update BOTH domains atomically"); OK();
        CHECK(q1(fs.w, "SELECT reward_pool FROM supply_tracking")
                  == pool + 500, "pooled exactly once");
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
        mk_block(&mb, 2, &vburn, 1);
        CHECK(v2x_cmt_apply_ok(fs.w, &mb) == 0, "burn block");
        CHECK(q1(fs.w, "SELECT COUNT(*) FROM v2_domain_updates "
                       "WHERE global_height=2") == 1,
              "burn is CORE-local: exactly one update"); OK();
        CHECK(q1(fs.w, "SELECT domain_height FROM v2_domain_heads "
                       "WHERE domain_id=0") == sys_h_burn,
              "burn must not advance SYSTEM"); OK();
        CHECK(q1(fs.w, "SELECT total_burned FROM supply_tracking")
                  == burned + 100, "burned exactly once");
        CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "burn conserves");
        OK();

        /* (d) an adapter escape that mutates CORE without declaring it
         * trips the untouched-domain guard — block-level, a node FAULT
         * in the cometbft lane (whole-database digest). */
        uint8_t g0[64], g1[64];
        CHECK(v2x_db_digest(fs.w, g0) == 0, "digest");
        rogue_table_arm(fs.w);
        static v2x_env_t esneak;
        CHECK(env_sys_cc(&esneak, 999997, 5) == 0, "esneak");
        nodus_v2_envelope_t vsneak = { esneak.bytes, esneak.len };
        mk_block(&mb, 3, &vsneak, 1);
        CHECK(v2x_cmt_fault_why(fs.w, &mb, V2X_VERDICT,
                                "UNTOUCHED-DOMAIN GUARD") == 0,
              "undeclared issuance mutation accepted"); OK();
        rogue_table_disarm(fs.w);
        CHECK(v2x_db_digest(fs.w, g1) == 0 && memcmp(g0, g1, 64) == 0,
              "undeclared issuance mutation leaked state"); OK();

        /* (e) fault during a cross-domain native move rolls BOTH
         * domains, heads, roots, accounting and metadata back.
         *
         * cometbft lane: the block-level points on the lane's path are
         * node FAULTs (the host rolls back; whole-database digest). The
         * legacy phase-order point (after the CROSS phase) and the two
         * pre-BEGIN whole-batch points (F26 after the batch reserve, F27
         * after an envelope's exec) have no counterpart there; the
         * lane's own per-item points close the case instead — F38
         * between the move's two legs and F37 mid-leg (after the first
         * leg's first effect), each refusing the ITEM (EXEC) with the ledger
         * byte-identical, in a block that commits and so consumes a
         * height. */
        uint64_t accum2 = q1(fs.w, "SELECT epoch_pool_accum FROM "
                                   "epoch_state WHERE "
                                   "epoch_start_height=0");
        uint64_t amt3 = q1(fs.w, "SELECT amount FROM utxo_set WHERE "
                                 "nullifier=CAST(zeroblob(63)||x'01' AS "
                                 "BLOB)");
        uint64_t pool2 = q1(fs.w, "SELECT reward_pool FROM supply_tracking");
        static v2x_env_t emint2;
        CHECK(env_cross_fee_to_pool(&emint2, accum2 + 9, amt3 - 9,
                                    pool2 + 9) == 0, "emint2");
        nodus_v2_envelope_t vmint2 = { emint2.bytes, emint2.len };
        static const nodus_v2_apply_fail_t xpts[] = {
            V2AP_FAIL_AFTER_SUPPLY_MUT,
            V2AP_FAIL_AFTER_UPDATES, V2AP_FAIL_AFTER_HEADS,
            V2AP_FAIL_AFTER_BLOCK_META, V2AP_FAIL_BEFORE_COMMIT
        };
        for (size_t i = 0; i < sizeof(xpts) / sizeof(xpts[0]); i++) {
            mk_block(&mb, 3, &vmint2, 1);
            mb.fail_at = xpts[i];
            mb.fail_env_index = 0;
            CHECK(v2x_cmt_fault_why(fs.w, &mb, V2X_VERDICT,
                                    "fault-injection point") == 0,
                  "cross-move fault did not fail");
            CHECK(v2x_db_digest(fs.w, g1) == 0 &&
                  memcmp(g0, g1, 64) == 0,
                  "cross-move fault leaked one domain's half");
        }
        OK();
        uint64_t hx = 3;
        {
            uint32_t xcode = 0;
            mk_block(&mb, hx++, &vmint2, 1);
            mb.fail_at = V2AP_FAIL_AFTER_LEG_APPLY;
            mb.fail_env_index = 0;
            mb.fail_leg_index = 0;              /* after the SYSTEM leg  */
            CHECK(v2x_cmt_refused(fs.w, &mb, 0, &xcode) == 0 &&
                  xcode == NODUS_V2_TX_ERR_EXEC,
                  "cross-move fault leaked one domain's half"); OK();
            mk_block(&mb, hx++, &vmint2, 1);
            mb.fail_at = V2AP_FAIL_AFTER_EFFECT_APPLY;
            mb.fail_env_index = 0;
            mb.fail_effect_index = 0;   /* fires after effect 0 of the
                                         * FIRST leg that has one — the
                                         * SYSTEM leg (exec_one_env)    */
            CHECK(v2x_cmt_refused(fs.w, &mb, 0, &xcode) == 0 &&
                  xcode == NODUS_V2_TX_ERR_EXEC,
                  "cross-move fault leaked one domain's half"); OK();
        }
        /* determinism after failed attempts: the same move with no
         * fault commits, proving no meter/budget residue from the
         * refused attempts survived */
        mk_block(&mb, hx++, &vmint2, 1);
        CHECK(v2x_cmt_apply_ok(fs.w, &mb) == 0,
              "post-fault clean apply"); OK();
        CHECK(nodus_witness_v2_supply_check(fs.w) == 0, "conserved");
    }
    fx_close(&fs);

    printf("test_v2_apply: ALL %d checks passed\n", g_checks);
    return 0;
}
