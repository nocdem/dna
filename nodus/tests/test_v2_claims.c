/**
 * Nodus — Ledger V2 S6: witness manifest/claims integration + the
 * GENERICITY suite (INACTIVE).
 *
 * Rollback claims are NEVER made from return codes alone: db_state_digest
 * serializes EVERY table into one SHA3-512 and the tests byte-compare it
 * around every reject/fault (the test_v2_apply discipline).
 *
 * Sections:
 *   1. Schema v6 migration matrix: 0→6, 5→6, idempotent 6, unknown 7
 *      fail-close, per-stage fault rollback (digest-proven, version
 *      stays 5), restart persistence.
 *   2. Genesis with an ABSENT-distribution manifest: real manifest_root
 *      (1 leaf) inside the committed SYSTEM head root, independent
 *      reconstruction, independent second fixture → byte-identical
 *      roots, no unclaimed value.
 *   3. Genesis with a PRESENT-distribution manifest targeting the
 *      NATIVE CORE runtime (synthetic generic data, real ML-DSA-87
 *      keys): manifest/dist-state seeding (explicit target domain +
 *      asset), supply gate with the unclaimed-distribution owner,
 *      snapshot + manifest root reconstruction byte-identity, chain_id
 *      derived through the REAL genesis BlockID.
 *   4. Claim lifecycle (CORE target): multi-claim block; deterministic
 *      output created BY THE CORE RUNTIME HOOK (amount, owner, EXPLICIT
 *      domain ownership, created_at = 0); remaining decrement;
 *      claims_root reconstruction; supply holds; supply_tracking
 *      UNTOUCHED (a claim never mints); SYSTEM head does not advance.
 *   5. Adversarial matrix (every reject digest-proven no-op):
 *      early / late (post-deadline RETAIN) / duplicate-in-block /
 *      already-spent / destination substitution (leaf tamper AND wrong
 *      key) / bad signature / wrong amount / corrupt proof / wrong
 *      index / out-of-range index / unknown manifest hash / cross-chain
 *      replay.
 *   6. Insertion-order independence: same claims, reversed order in the
 *      same block on an identical twin fixture → byte-identical
 *      claims_root / core / global roots.
 *   7. Fault injection F16/F17/F18 (the S6 claim stages) + F13 with a
 *      claim aboard: rc −1 and the FULL DB digest is byte-identical.
 *   8. Restart persistence + idempotent replay; spent-claim survives
 *      reopen and re-claims reject.
 *   9. Never-mint: a manifest committing LESS than the snapshot sum —
 *      the remaining-value gate rejects the overdraw and rolls back.
 *  10. Genesis manifest rejects: wrong domain hash / wrong domain count
 *      / supply mismatch / unregistered target domain / asset the
 *      target runtime refuses — whole genesis rolled back.
 *  11. Inactive boundary: V2 admission rejects tx types 12-14 (the
 *      claim path has NO live transaction type).
 *  12. GENERICITY — synthetic registered domain T3 (id 7, NOT 1):
 *      genesis with 3 registered domains; a distribution EXPLICITLY
 *      targeting T3 with a T3-only asset; claims route through T3's
 *      REGISTERED claim hook (invocation-counted), create T3's OWN
 *      domain-local output and NEVER touch utxo_set (no default
 *      domain anywhere); T3's head advances, CORE's does not; the
 *      T3-asset unclaimed value is NEVER summed into the DNAC
 *      equation; nullifiers of different domains/assets cannot
 *      collide; cross-manifest/domain/asset replay rejects; a
 *      SYSTEM+CORE+T3 block faults roll back completely (digest);
 *      a sidecar claim cannot slip past a follower root expectation.
 *  13. COEXISTENCE — T3 and T4 (two synthetic runtimes) registered
 *      together: 4-domain genesis, both runtimes drive their own
 *      state, Header/BlockID/schema untouched.
 *
 * @file test_v2_claims.c
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_roots_v2.h"
#include "nodus/nodus_chain_config.h"

#include "v2_exec_fixture.h"
#include "v2_genesis_fixture.h"

#include "dnac/manifest_wire.h"
#include "dnac/domain_wire.h"
#include "dnac/block_v2.h"
#include "dnac/tx_wire.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

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
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

/* ── fs + fixture (test_v2_apply discipline) ────────────────────────── */
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
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_claims_XXXXXX");
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain_id16, 0x36, sizeof(fx->chain_id16));
    if (nodus_witness_create_chain_db(fx->w, fx->chain_id16) != 0) {
        rmrf(fx->dir); free(fx->w); fx->w = NULL;
        return -1;
    }
    nodus_chain_config_db_migrate(fx->w);
    return 0;
}

static int fx_reopen(fixture_t *fx) {
    const struct nodus_domain_runtime *tbl = fx->w->v2_runtime_table;
    size_t tbl_n = fx->w->v2_runtime_table_n;
    sqlite3_close(fx->w->db);
    fx->w->db = NULL;
    int rc = nodus_witness_create_chain_db(fx->w, fx->chain_id16);
    fx->w->v2_runtime_table = tbl;      /* the compiled table survives a
                                         * restart in production too    */
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

/* ── deterministic keys + synthetic generic snapshot ────────────────── */

#define N_LEAVES 3
static uint8_t g_pk[N_LEAVES][QGP_DSA87_PUBLICKEYBYTES];
static uint8_t g_sk[N_LEAVES][QGP_DSA87_SECRETKEYBYTES];
static dna_dist_leaf_t g_leaf[N_LEAVES];
static uint8_t g_leaf_hash[N_LEAVES][64];
static uint8_t g_snapshot_root[64];

static const uint8_t g_native_asset[64] = {0};   /* CORE: native token  */

/* conv 3/2 FLOOR: 10→15, 5→7, 7→10; Σ = 32 */
static const uint64_t g_src_amount[N_LEAVES]  = { 10, 5, 7 };
static const uint64_t g_conv_amount[N_LEAVES] = { 15, 7, 10 };
static const char    *g_src_id[N_LEAVES] =
    { "src-alpha", "src-beta", "src-gamma" };

static int keys_init(void) {
    for (int i = 0; i < N_LEAVES; i++) {
        uint8_t seed[32];
        memset(seed, 0x40 + i, sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_pk[i], g_sk[i], seed) != 0)
            return -1;
        memset(&g_leaf[i], 0, sizeof(g_leaf[i]));
        g_leaf[i].leaf_version = DNA_DIST_VERSION;
        g_leaf[i].source_id_len = (uint16_t)strlen(g_src_id[i]);
        memcpy(g_leaf[i].source_id, g_src_id[i], g_leaf[i].source_id_len);
        g_leaf[i].source_amount = g_src_amount[i];
        if (qgp_sha3_512(g_pk[i], QGP_DSA87_PUBLICKEYBYTES,
                         g_leaf[i].dest_binding) != 0)
            return -1;
        if (dna_dist_leaf_hash(&g_leaf[i], g_leaf_hash[i]) != 0)
            return -1;
    }
    if (dna_dist_snapshot_root(g_leaf, N_LEAVES, g_snapshot_root) != 0)
        return -1;
    if (dna_dist_check_totals(g_leaf, N_LEAVES, 3, 2,
                              DNA_DISTROUND_FLOOR, 32) != 0)
        return -1;
    return 0;
}

/* ── synthetic runtimes T3 / T4 (registered test domains) ───────────── */

#define T3_DOMAIN 7u
#define T4_DOMAIN 9u
static const uint8_t T3_ASSET[5] = { 'T', '3', 'A', 'S', 'T' };
static const uint8_t T4_ASSET[5] = { 'T', '4', 'A', 'S', 'T' };

static int g_t3_claim_hook_calls = 0;
static int g_t3_invariant_calls = 0;

/* one shared shape for both synthetic runtimes: a private state table
 * "tN_state" (id BLOB PK, amount, asset) + a tagged root over it */
static int tn_state_root(const char *table, const char *tag16,
                         nodus_witness_t *w, uint8_t out[64]) {
    char sql[128];
    snprintf(sql, sizeof(sql),
             "SELECT id, amount FROM %s ORDER BY id ASC", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    dyn_t d = { 0 };
    int rc, ret = -1;
    if (dyn_put(&d, tag16, 16) != 0) goto done;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const void *id = sqlite3_column_blob(st, 0);
        int idl = sqlite3_column_bytes(st, 0);
        sqlite3_int64 amt = sqlite3_column_int64(st, 1);
        if (!id || idl != 64 || amt < 0) goto done;
        uint8_t a8[8];
        for (int i = 0; i < 8; i++)
            a8[i] = (uint8_t)(((uint64_t)amt >> (56 - 8 * i)) & 0xff);
        if (dyn_put(&d, id, 64) != 0 || dyn_put(&d, a8, 8) != 0)
            goto done;
    }
    if (rc != SQLITE_DONE) goto done;
    ret = qgp_sha3_512(d.buf, d.len, out) == 0 ? 0 : -1;
done:
    sqlite3_finalize(st);
    free(d.buf);
    return ret;
}

static int t3_state_root(const nodus_domain_runtime_t *rt,
                         struct nodus_witness *w, uint8_t out[64]) {
    (void)rt;
    return tn_state_root("t3_state", "T3.STATE.v1\0\0\0\0\0",
                         (nodus_witness_t *)w, out);
}
static int t4_state_root(const nodus_domain_runtime_t *rt,
                         struct nodus_witness *w, uint8_t out[64]) {
    (void)rt;
    return tn_state_root("t4_state", "T4.STATE.v1\0\0\0\0\0",
                         (nodus_witness_t *)w, out);
}

static int tn_asset_check(const uint8_t *want5, const uint8_t *ref,
                          uint16_t len) {
    return (ref && len == 5 && memcmp(ref, want5, 5) == 0) ? 0 : -1;
}
static int t3_asset_check(const nodus_domain_runtime_t *rt,
                          const uint8_t *ref, uint16_t len) {
    (void)rt;
    return tn_asset_check(T3_ASSET, ref, len);
}
static int t4_asset_check(const nodus_domain_runtime_t *rt,
                          const uint8_t *ref, uint16_t len) {
    (void)rt;
    return tn_asset_check(T4_ASSET, ref, len);
}

static int tn_claim_apply(const char *table, nodus_witness_t *w,
                          const nodus_rt_claim_t *claim,
                          uint8_t out_output_id[64]) {
    uint8_t oid[64];
    if (dna_claim_utxo_id(claim->nullifier, oid) != 0) return -1;
    char sql[160];
    snprintf(sql, sizeof(sql),
             "INSERT INTO %s (id, amount, asset) VALUES (?1, ?2, ?3)",
             table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, oid, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)claim->amount);
    sqlite3_bind_blob(st, 3, claim->asset_ref, claim->asset_ref_len,
                      SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;
    memcpy(out_output_id, oid, 64);
    return 0;
}
static int t3_claim_apply(const nodus_domain_runtime_t *rt,
                          struct nodus_witness *w,
                          const nodus_rt_claim_t *claim,
                          uint8_t out_output_id[64]) {
    if (t3_asset_check(rt, claim->asset_ref, claim->asset_ref_len) != 0)
        return -1;
    g_t3_claim_hook_calls++;
    return tn_claim_apply("t3_state", (nodus_witness_t *)w, claim,
                          out_output_id);
}
static int t4_claim_apply(const nodus_domain_runtime_t *rt,
                          struct nodus_witness *w,
                          const nodus_rt_claim_t *claim,
                          uint8_t out_output_id[64]) {
    if (t4_asset_check(rt, claim->asset_ref, claim->asset_ref_len) != 0)
        return -1;
    return tn_claim_apply("t4_state", (nodus_witness_t *)w, claim,
                          out_output_id);
}

static int t3_invariant(const nodus_domain_runtime_t *rt,
                        struct nodus_witness *w) {
    (void)rt; (void)w;
    g_t3_invariant_calls++;             /* dispatch reached the runtime  */
    return 0;                           /* T3's asset is fully internal  */
}

/* ── T3/T4 test adapter (execution season): one compiled adapter for
 * both synthetic domains — the table is picked from the AUTHORITATIVE
 * domain id the boundary hands in (7 → t3_state, 9 → t4_state), which
 * is exactly the domain-scoping discipline a real adapter must apply.
 * op 1: CREATE, key = 64-byte id, value = amount u64 BE ‖ asset bytes. */
#define TN_OP_PUT 1u

static const char *tn_table_for(uint32_t dom) {
    return dom == T3_DOMAIN ? "t3_state"
         : dom == T4_DOMAIN ? "t4_state" : NULL;
}

static nodus_adapter_status_t tn_probe(
        const nodus_domain_adapter_t *ad, struct nodus_witness *wns,
        uint32_t dom, const nodus_adapter_op_t *op,
        const uint8_t *key, uint16_t key_len,
        nodus_adapter_row_facts_t *f) {
    (void)ad; (void)op;
    const char *tbl = tn_table_for(dom);
    if (!tbl) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    nodus_witness_t *w = (nodus_witness_t *)wns;
    char sql[96];
    snprintf(sql, sizeof(sql), "SELECT amount FROM %s WHERE id=?1", tbl);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    sqlite3_bind_blob(st, 1, key, key_len, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        f->exists = 1;
        f->version = (uint64_t)sqlite3_column_int64(st, 0);
    } else if (rc == SQLITE_DONE) {
        f->exists = 0;
    } else {
        sqlite3_finalize(st);
        return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    }
    sqlite3_finalize(st);
    return NODUS_ADAPTER_OK;
}

static nodus_adapter_status_t tn_mutate(
        const nodus_domain_adapter_t *ad, struct nodus_witness *wns,
        uint32_t dom, const nodus_adapter_op_t *op, uint8_t kind,
        const uint8_t *key, uint16_t key_len,
        const uint8_t *value, uint32_t value_len) {
    (void)ad; (void)op;
    if (kind != DNA_EFFECT_CREATE || value_len < 8)
        return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    const char *tbl = tn_table_for(dom);
    if (!tbl) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    nodus_witness_t *w = (nodus_witness_t *)wns;
    uint64_t amt = 0;
    for (int i = 0; i < 8; i++) amt = (amt << 8) | value[i];
    char sql[128];
    snprintf(sql, sizeof(sql),
             "INSERT INTO %s (id, amount, asset) VALUES (?1, ?2, ?3)",
             tbl);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    sqlite3_bind_blob(st, 1, key, key_len, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)amt);
    sqlite3_bind_blob(st, 3, value + 8, (int)(value_len - 8),
                      SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? NODUS_ADAPTER_OK
                             : NODUS_ADAPTER_ERR_STORAGE_FAULT;
}

static const nodus_adapter_op_t TN_OPS[1] = {
    { TN_OP_PUT, NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_CREATE),
      NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_ABSENT), 64, 64, 8, 64 }
};

static const nodus_domain_adapter_t TN_ADAPTER = {
    .adapter_version = NODUS_DOMAIN_ADAPTER_V1,
    .ops = TN_OPS,
    .n_ops = 1,
    .probe = tn_probe,
    .mutate = tn_mutate,
    .read = NULL                        /* T3/T4 serve no mediated reads */
};

/* Build the extended runtime table: the two production natives + the
 * synthetic ones. NOTHING in a Header, BlockID, QC or schema changes to
 * carry them — that is the point. */
static nodus_domain_runtime_t g_ext_table[4];
static size_t g_ext_n = 0;
static const uint32_t TN_RULES[1] = { 1 };

static int ext_table_init(void) {
    size_t n = 0;
    const nodus_domain_runtime_t *b = nodus_runtime_builtin_table(&n);
    if (!b || n != 2) return -1;
    memcpy(&g_ext_table[0], &b[0], sizeof(b[0]));
    memcpy(&g_ext_table[1], &b[1], sizeof(b[1]));
    /* the scripted execution surface (execution season) — the identity
     * tuples stay byte-identical to the builtins */
    g_ext_table[0].auth = v2x_auth;
    g_ext_table[0].read_plan = v2x_read_plan;
    g_ext_table[0].exec = v2x_exec;
    g_ext_table[0].adapter = &V2X_SYS_ADAPTER;
    g_ext_table[1].auth = v2x_auth;
    g_ext_table[1].read_plan = v2x_read_plan;
    g_ext_table[1].exec = v2x_exec;
    g_ext_table[1].adapter = &V2X_CORE_ADAPTER;

    memset(&g_ext_table[2], 0, sizeof(g_ext_table[2]));
    g_ext_table[2].domain_id = T3_DOMAIN;
    g_ext_table[2].runtime_kind = DNA_RUNTIME_NATIVE_BUILTIN;
    g_ext_table[2].runtime_abi = NODUS_DOMAIN_RUNTIME_ABI_V1;
    g_ext_table[2].ruleset_version = 1;
    g_ext_table[2].descriptor.descriptor_version = DNA_RULESET_DESC_VERSION;
    g_ext_table[2].descriptor.domain_id = T3_DOMAIN;
    memcpy(g_ext_table[2].descriptor.name, "TEST_DOMAIN_3", 13);
    g_ext_table[2].descriptor.runtime_abi = NODUS_DOMAIN_RUNTIME_ABI_V1;
    g_ext_table[2].descriptor.ruleset_version = 1;
    g_ext_table[2].descriptor.rule_count = 1;
    g_ext_table[2].descriptor.rule_ids = TN_RULES;
    g_ext_table[2].descriptor.tx_type_count = 0;
    g_ext_table[2].descriptor.tx_types = NULL;
    if (dna_ruleset_desc_hash(&g_ext_table[2].descriptor,
                              g_ext_table[2].ruleset_hash) != 0)
        return -1;
    g_ext_table[2].admit = b[0].admit;
    g_ext_table[2].tx_cost = b[0].tx_cost;
    g_ext_table[2].state_root = t3_state_root;
    g_ext_table[2].asset_check = t3_asset_check;
    g_ext_table[2].claim_apply = t3_claim_apply;
    g_ext_table[2].invariant = t3_invariant;
    g_ext_table[2].auth = v2x_auth;
    /* capacity season: a synthetic runtime must declare its auth-kind
     * allowlist or the engine's admission scan rejects every leg */
    g_ext_table[2].allowed_auth_kinds =
        NODUS_RT_AUTHKIND_BIT(NODUS_RT_AUTHKIND_DSA87_MULTI_V1);
    g_ext_table[2].read_plan = v2x_read_plan;
    g_ext_table[2].exec = v2x_exec;
    g_ext_table[2].adapter = &TN_ADAPTER;

    memcpy(&g_ext_table[3], &g_ext_table[2], sizeof(g_ext_table[2]));
    g_ext_table[3].domain_id = T4_DOMAIN;
    g_ext_table[3].descriptor.domain_id = T4_DOMAIN;
    memset(g_ext_table[3].descriptor.name, 0, DNA_DOM_NAME_LEN);
    memcpy(g_ext_table[3].descriptor.name, "TEST_DOMAIN_4", 13);
    if (dna_ruleset_desc_hash(&g_ext_table[3].descriptor,
                              g_ext_table[3].ruleset_hash) != 0)
        return -1;
    g_ext_table[3].state_root = t4_state_root;
    g_ext_table[3].asset_check = t4_asset_check;
    g_ext_table[3].claim_apply = t4_claim_apply;
    g_ext_table[3].invariant = NULL;    /* NULL = no asset state claimed */
    g_ext_n = 4;
    return 0;
}

/* Rewrite a domain's registry record with a new lifecycle status (the
 * fixture-level shortcut test_v2_apply's quota section established). */
static int set_domain_status(nodus_witness_t *w, uint32_t domain_id,
                             uint8_t status) {
    dna_domreg_record_t rec;
    if (nodus_witness_domreg_get(w, domain_id, &rec, NULL, NULL) != 0)
        return -1;
    rec.status = status;
    uint8_t recb[DNA_DOMREG_REC_ENC_LEN];
    if (dna_domreg_record_encode(&rec, recb) != 0) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "UPDATE domain_registry SET record=?1 WHERE domain_id=?2",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, recb, sizeof(recb), SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)domain_id);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* Build a SYSTEM-op SQL string performing the same record rewrite —
 * the registry transition a block carries (lifecycle tests). The
 * returned buffer is malloc'd; caller frees AFTER the block applied. */
static char *status_update_sql(nodus_witness_t *w, uint32_t domain_id,
                               uint8_t status) {
    dna_domreg_record_t rec;
    if (nodus_witness_domreg_get(w, domain_id, &rec, NULL, NULL) != 0)
        return NULL;
    rec.status = status;
    uint8_t recb[DNA_DOMREG_REC_ENC_LEN];
    if (dna_domreg_record_encode(&rec, recb) != 0) return NULL;
    char *sql = malloc(2 * DNA_DOMREG_REC_ENC_LEN + 128);
    if (!sql) return NULL;
    char *p = sql + snprintf(sql, 64,
                             "UPDATE domain_registry SET record=x'");
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < DNA_DOMREG_REC_ENC_LEN; i++) {
        *p++ = hexd[recb[i] >> 4];
        *p++ = hexd[recb[i] & 0x0f];
    }
    snprintf(p, 48, "' WHERE domain_id=%u", domain_id);
    return sql;
}

/* Register a synthetic domain (status REGISTERED — the generic
 * registration path; genesis_state_root = the runtime's REAL current
 * root, which the canonical activation constructor later re-checks). */
static int register_synthetic_only(nodus_witness_t *w,
                                   const nodus_domain_runtime_t *rt) {
    dna_domain_manifest_t m;
    memset(&m, 0, sizeof(m));
    m.manifest_version = DNA_DOMMAN_VERSION;
    m.domain_id = rt->domain_id;
    memcpy(m.name, rt->descriptor.name, DNA_DOM_NAME_LEN);
    m.runtime_kind = rt->runtime_kind;
    m.runtime_abi = rt->runtime_abi;
    m.ruleset_version = rt->ruleset_version;
    memcpy(m.ruleset_hash, rt->ruleset_hash, 64);
    m.tx_type_count = 0;
    m.fee_policy = DNA_FEEPOL_GLOBAL_BURN;
    m.upgrade_authority = DNA_UPGAUTH_CHAIN_CONFIG;
    m.readiness_policy = DNA_RDYPOL_STAGED_V1;
    if (rt->state_root(rt, w, m.genesis_state_root) != 0) return -1;
    return nodus_witness_domreg_op_register(w, &m);
}

/* Register + flip ACTIVE before genesis (the genesis block then IS the
 * domain's activation block). */
static int register_synthetic(nodus_witness_t *w,
                              const nodus_domain_runtime_t *rt) {
    if (register_synthetic_only(w, rt) != 0) return -1;
    return set_domain_status(w, rt->domain_id, DNA_DOMST_ACTIVE);
}

/* ── manifest + genesis builders ────────────────────────────────────── */

/* The REAL DomainManifest hashes: pre-run the (idempotent) registry
 * genesis, then hash the stored manifests — genesis_ex re-runs it and
 * byte-compares, so state must not move in between (it doesn't). */
static int domman_hash_of(nodus_witness_t *w, uint32_t dom,
                          uint8_t out[64]) {
    dna_domain_manifest_t m;
    if (nodus_witness_domreg_get(w, dom, NULL, &m, NULL) != 0) return -1;
    return dna_domman_hash(&m, out);
}

static int domman_hashes(nodus_witness_t *w, uint8_t sys_h[64],
                         uint8_t core_h[64]) {
    /* O14: seed the committed validator authority BEFORE the registry
     * commits genesis_state_root — the vset leg feeds the SYSTEM payload
     * root, and genesis_ex re-derives it and byte-compares. Every V2
     * block also needs a resolvable snapshot to be applied at all. */
    if (v2x_seed_authority(w) != 0) return -1;
    if (nodus_witness_domreg_init_genesis(w) != 0) return -1;
    if (domman_hash_of(w, DNA_DOMAIN_SYSTEM, sys_h) != 0) return -1;
    return domman_hash_of(w, DNA_DOMAIN_CORE, core_h);
}

static void gman_base(dna_gman_t *m, uint64_t supply,
                      const uint8_t sys_h[64], const uint8_t core_h[64]) {
    memset(m, 0, sizeof(*m));
    m->manifest_version = DNA_GMAN_VERSION;
    m->genesis_supply_raw = supply;
    m->domain_count = 2;
    m->domains[0].domain_id = DNA_DOMAIN_SYSTEM;
    memcpy(m->domains[0].manifest_hash, sys_h, 64);
    m->domains[1].domain_id = DNA_DOMAIN_CORE;
    memcpy(m->domains[1].manifest_hash, core_h, 64);
    m->dist_present = 0;
}

static void gman_dist(dna_gman_t *m, uint64_t total,
                      uint64_t start_h, uint64_t end_h,
                      const char *tag, uint32_t target_domain,
                      const uint8_t *asset, uint16_t asset_len) {
    m->dist_present = 1;
    m->dist_version = DNA_DIST_VERSION;
    m->target_domain_id = target_domain;
    m->target_asset_len = asset_len;
    memcpy(m->target_asset_ref, asset, asset_len);
    m->source_tag_len = (uint16_t)strlen(tag);
    memcpy(m->source_tag, tag, m->source_tag_len);
    m->source_commit_len = 16;
    memset(m->source_commit, 0x77, 16);
    memcpy(m->snapshot_root, g_snapshot_root, 64);
    m->leaf_count = N_LEAVES;
    m->conv_numerator = 3;
    m->conv_denominator = 2;
    m->rounding_mode = DNA_DISTROUND_FLOOR;
    m->excluded_amount = 4;
    m->total_claimable = total;
    m->claim_start_height = start_h;
    m->claim_end_height = end_h;
    m->auth_mode = DNA_CLAIMAUTH_DNA_NATIVE;
    m->fee_mode = DNA_CLAIMFEE_NONE;
    m->post_deadline_mode = DNA_POSTDL_RETAIN;
}

/* Genesis BlockID through the REAL derivation: BlockHeader V2 with the
 * all-zero chain_id ‖ the canonical manifest bytes (block_v2.h). */
/* ── O14: the genesis identity is DERIVED, not predicted ─────────────
 * The retired `genesis_id_of` used to compute the genesis BlockID from a
 * header with ZEROED roots and hand it to genesis_ex as the id to store.
 * The engine now builds the genesis header from its OWN derived global
 * root and binds that into the preimage, so a zero-root prediction can
 * never match. Commit with the assertion omitted and read the committed
 * identity back — chain_id is the id's first 32 bytes (block_v2.h).
 *
 * Also seeds the committed validator authority every V2 block needs
 * (v2x_seed_authority) BEFORE genesis, since the vset leg feeds the
 * SYSTEM payload root that genesis re-derives and byte-compares. */
static int commit_genesis_read(fixture_t *fx, const uint8_t *mbytes,
                               size_t mlen, uint8_t out_gid[64],
                               uint8_t out_chain[32]) {
    uint8_t vset[64], gid[64];
    memset(vset, 0x77, 64);
    /* O14 review R1-F2: genesis binds validator_set_hash into the chain
     * identity and the engine requires it to EQUAL the committed epoch-0
     * authority, so hand over the COMMITTED hash rather than a chosen
     * one. (v2x_seed_authority already ran in domman_hashes.) */
    {
        dna_vset_snapshot_t *s0 = NULL;
        uint32_t sn = 0, sq = 0;
        if (nodus_witness_v2_epoch_authority_for_height(fx->w, 0, &s0,
                                                        &sn, &sq) == 0 &&
            s0) {
            int hrc = dna_vset_hash(s0, vset);
            dna_vset_free(&s0);
            if (hrc != 0) return -1;
        } else {
            dna_vset_free(&s0);
        }
    }
    if (nodus_witness_v2_genesis_ex(fx->w, NULL, vset, 0, mbytes, mlen)
        != 0)
        return -1;
    if (v2x_block_id_at(fx->w, 0, gid) != 0) return -1;
    if (out_gid)   memcpy(out_gid, gid, 64);
    if (out_chain) memcpy(out_chain, gid, 32);
    return 0;
}

/* Seed supply so that genesis + minted − burned == utxo + unclaimed
 * (native-target case) — utxo rows carry EXPLICIT CORE ownership. */
/* O15J Faz 2 — INFLATION OFF for this file's fixtures.
 *
 * The V1 economics port makes every block mint, and a mint moves both
 * supply_tracking (a CORE root leg) and epoch_state (a SYSTEM leg). This
 * file tests the S6 CLAIM pipeline — distribution roots, nullifiers,
 * replay, per-domain claims_root ownership — and asserts a supply
 * composition it controls exactly (`total_minted == 0`). Emission would
 * make that composition a moving target and the assertions would have to
 * be loosened, which deletes the property they exist to pin.
 *
 * So inflation is turned OFF for these chains rather than the assertions
 * being weakened. Emission has its own coverage in test_v2_econ, which
 * builds its own fixtures and runs the LIVE conservation invariant.
 *
 * Seeded BEFORE genesis so the row is part of the committed genesis
 * state on every fixture in this file uniformly — chain_config_history
 * is a SYSTEM root leg, so a row added AFTER genesis would move a root
 * the twins compare. The warm cache is cleared explicitly because this
 * raw INSERT bypasses the mutate path that would invalidate it. */
static int seed_inflation_off(nodus_witness_t *w) {
    char cc[320];
    snprintf(cc, sizeof(cc),
        "INSERT OR REPLACE INTO chain_config_history (param_id, new_value,"
        " effective_block, commit_block, tx_hash, proposal_nonce,"
        " created_at_unix) VALUES (%d, 0, 0, 0, zeroblob(64), 0, 0)",
        (int)DNAC_CFG_INFLATION_START_BLOCK);
    if (run_sql(w->db, cc) != 0) return -1;
    w->chain_config_cache_warm = false;
    return 0;
}

static int seed_supply(nodus_witness_t *w, uint64_t genesis_supply,
                       uint64_t utxo_amount) {
    if (seed_inflation_off(w) != 0) return -1;
    char sql[640];
    snprintf(sql, sizeof(sql),
        "INSERT INTO supply_tracking (id, genesis_supply, total_burned, "
        "total_minted, current_supply, last_tx_hash, last_sequence) "
        "VALUES (1, %llu, 0, 0, %llu, x'00', 0)",
        (unsigned long long)genesis_supply,
        (unsigned long long)genesis_supply);
    if (run_sql(w->db, sql) != 0) return -1;
    snprintf(sql, sizeof(sql),
        "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
        "tx_hash, output_index, block_height, created_at, unlock_block, "
        "domain_id) "
        "VALUES (zeroblob(63)||x'01', 'genesis', %llu, zeroblob(64), "
        "zeroblob(63)||x'aa', 0, 0, 0, 0, 1)",
        (unsigned long long)utxo_amount);
    return run_sql(w->db, sql);
}

/* Full present-distribution genesis on a fresh fixture (CORE-native
 * target). Outputs the derived chain id + genesis block id + the
 * committed manifest hash. */
static int dist_genesis(fixture_t *fx, uint64_t total, uint64_t start_h,
                        uint64_t end_h, const char *tag,
                        uint8_t out_chain[32], uint8_t out_gid[64],
                        uint8_t out_mh[64]) {
    if (nodus_witness_db_migrate_v2s9(fx->w) != 0) return -1;
    if (seed_supply(fx->w, 1000, 1000 - total) != 0) return -1;
    uint8_t sys_h[64], core_h[64];
    if (domman_hashes(fx->w, sys_h, core_h) != 0) return -1;
    dna_gman_t m;
    gman_base(&m, 1000, sys_h, core_h);
    gman_dist(&m, total, start_h, end_h, tag, DNA_DOMAIN_CORE,
              g_native_asset, 64);
    uint8_t mbytes[8192];
    size_t mlen = 0;
    if (dna_gman_encode(&m, mbytes, sizeof(mbytes), &mlen) != 0) return -1;
    if (out_mh && dna_gman_hash(&m, out_mh) != 0) return -1;
    return commit_genesis_read(fx, mbytes, mlen, out_gid, out_chain);
}

/* ── claim + block builders ─────────────────────────────────────────── */

static int make_claim(dna_claim_t *c, int leaf, const uint8_t chain[32],
                      const uint8_t manifest_hash[64]) {
    memset(c, 0, sizeof(*c));
    c->claim_version = DNA_CLAIM_VERSION;
    memcpy(c->chain_id, chain, 32);
    memcpy(c->manifest_hash, manifest_hash, 64);
    c->leaf_index = (uint64_t)leaf;
    c->source_id_len = g_leaf[leaf].source_id_len;
    memcpy(c->source_id, g_leaf[leaf].source_id, c->source_id_len);
    c->source_amount = g_leaf[leaf].source_amount;
    memcpy(c->dest_binding, g_leaf[leaf].dest_binding, 64);
    uint16_t ns = 0;
    if (dna_dist_proof_build((const uint8_t (*)[64])g_leaf_hash, N_LEAVES,
                             (uint64_t)leaf, c->siblings, &ns) != 0)
        return -1;
    c->n_siblings = ns;
    c->auth_mode = DNA_CLAIMAUTH_DNA_NATIVE;
    memcpy(c->pubkey, g_pk[leaf], QGP_DSA87_PUBLICKEYBYTES);
    uint8_t pre[DNA_CLAIM_PREIMAGE_MAX];
    size_t pre_len = 0;
    if (dna_claim_preimage(c, pre, &pre_len) != 0) return -1;
    size_t siglen = 0;
    if (qgp_dsa87_sign(c->signature, &siglen, pre, pre_len,
                       g_sk[leaf]) != 0 || siglen != DNA_CLAIM_SIG_LEN)
        return -1;
    return 0;
}

static void mk_id(uint8_t out[64], uint8_t fill) { memset(out, fill, 64); }

static void mk_claim_block(nodus_v2_block_t *b, uint64_t h,
                           const uint8_t gen_id[64],
                           const dna_claim_t *claims, size_t n_claims) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = 0;
    /* O14 leader mode: identity is DERIVED, never carried. */
    (void)gen_id;
    b->claims = claims;
    b->n_claims = n_claims;
}

/* One-envelope block (typed path). The envelope buffer must OUTLIVE the
 * apply call (view lifetime rule), so callers pass persistent v2x_env_t
 * storage and this helper only wires the reference. */
static nodus_v2_envelope_t g_env_ref;

static void mk_env_block(nodus_v2_block_t *b, uint64_t h,
                         const uint8_t gid[64], const v2x_env_t *e) {
    mk_claim_block(b, h, gid, NULL, 0);
    if (e) {
        g_env_ref.env_bytes = e->bytes;
        g_env_ref.env_len = e->len;
        b->envs = &g_env_ref;
        b->n_envs = 1;
    }
}

/* SYSTEM envelope: registry lifecycle transition through the typed
 * DOMREG_SET adapter op (the old status_update_sql op, typed).
 * `expiry` doubles as a distinctness salt: two lifecycle transitions
 * that would otherwise carry byte-identical envelopes (e.g. an
 * ACTIVATE and a later RESUME to the same record bytes) would derive
 * ONE tx_id — and the committed transaction index correctly refuses an
 * identity replay. Distinct transactions must be distinct bytes. */
static int env_status(v2x_env_t *e, nodus_witness_t *w, uint32_t dom,
                      uint8_t status, uint64_t expiry) {
    dna_domreg_record_t rec;
    if (nodus_witness_domreg_get(w, dom, &rec, NULL, NULL) != 0) return -1;
    rec.status = status;
    uint8_t recb[DNA_DOMREG_REC_ENC_LEN];
    if (dna_domreg_record_encode(&rec, recb) != 0) return -1;
    uint8_t key[4];
    v2x_put32(key, dom);
    dna_effect_in_t eff;
    memset(&eff, 0, sizeof(eff));
    eff.hdr.op_id = V2X_OP_DOMREG;
    eff.hdr.effect_kind = DNA_EFFECT_SET;
    eff.hdr.precond_tag = DNA_EFFECT_PRE_EXISTS;
    eff.hdr.key_len = 4;
    eff.hdr.value_len = DNA_DOMREG_REC_ENC_LEN;
    eff.key = key;
    eff.value = recb;
    uint8_t res[1024];
    size_t rl = 0;
    if (dna_effect_result_encode(&eff, 1, res, sizeof(res), &rl) != 0)
        return -1;
    uint8_t call[1200];
    uint32_t cl = v2x_script_build(call, sizeof(call), NULL, 0, res, rl);
    if (!cl) return -1;
    v2x_leg_t leg = { 0, 1, call, cl, 4, 2048 };
    return v2x_env_build_ex(e, 200000, expiry, 0, &leg, 1);
}

/* T3/T4 envelope: one synthetic-domain row through the TN adapter. */
static int env_tn_put(v2x_env_t *e, uint32_t dom, uint8_t keylast,
                      uint64_t amount, const uint8_t asset5[5]) {
    uint8_t key[64] = { 0 };
    key[63] = keylast;
    uint8_t val[13];
    for (int i = 0; i < 8; i++)
        val[i] = (uint8_t)(amount >> (56 - 8 * i));
    memcpy(val + 8, asset5, 5);
    return v2x_env1(e, dom, 1, TN_OP_PUT, DNA_EFFECT_CREATE,
                    DNA_EFFECT_PRE_ABSENT, key, 64, val, 13);
}

static int utxo_row(nodus_witness_t *w, const uint8_t id[64],
                    uint64_t *amount, uint64_t *domain,
                    uint64_t *created_at, char owner[130]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT amount, domain_id, created_at, owner FROM utxo_set "
            "WHERE nullifier = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, id, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    int ret = -1;
    if (rc == SQLITE_ROW) {
        if (amount) *amount = (uint64_t)sqlite3_column_int64(st, 0);
        if (domain) *domain = (uint64_t)sqlite3_column_int64(st, 1);
        if (created_at)
            *created_at = (uint64_t)sqlite3_column_int64(st, 2);
        if (owner)
            snprintf(owner, 130, "%s",
                     (const char *)sqlite3_column_text(st, 3));
        ret = 0;
    } else if (rc == SQLITE_DONE) {
        ret = 1;
    }
    sqlite3_finalize(st);
    return ret;
}

/* claim's nullifier + output id, derived exactly as consensus does
 * (COMMITTED target context, never a default) */
static int claim_ids(const dna_claim_t *c, uint32_t target_domain,
                     const uint8_t *asset, uint16_t asset_len,
                     uint8_t nul[64], uint8_t oid[64]) {
    dna_dist_leaf_t leaf;
    memset(&leaf, 0, sizeof(leaf));
    leaf.leaf_version = DNA_DIST_VERSION;
    leaf.source_id_len = c->source_id_len;
    memcpy(leaf.source_id, c->source_id, c->source_id_len);
    leaf.source_amount = c->source_amount;
    memcpy(leaf.dest_binding, c->dest_binding, 64);
    uint8_t lh[64];
    if (dna_dist_leaf_hash(&leaf, lh) != 0) return -1;
    if (dna_claim_nullifier(c->chain_id, c->manifest_hash, target_domain,
                            asset, asset_len, lh, nul) != 0)
        return -1;
    return dna_claim_utxo_id(nul, oid);
}

/* apply a block that must REJECT, digest-proven no-op */
static int expect_reject(nodus_witness_t *w, nodus_v2_block_t *b,
                         const char *msg) {
    /* Both rejection classes count here — a consensus VERDICT (-1) and
     * a node-local FAULT (-2, e.g. this build cannot resolve an ACTIVE
     * domain's runtime) — because what THESE tests pin is the fail-
     * closed no-op: nothing persisted either way (digest-proven). */
    uint8_t d0[64], d1[64];
    if (db_state_digest(w, d0) != 0) return 1;
    int rc = nodus_witness_v2_apply_block(w, b);
    if (rc != -1 && rc != -2) {
        fprintf(stderr, "expected reject: %s (rc %d)\n", msg, rc);
        return 1;
    }
    if (db_state_digest(w, d1) != 0) return 1;
    if (memcmp(d0, d1, 64) != 0) {
        fprintf(stderr, "reject was not a no-op: %s\n", msg);
        return 1;
    }
    return 0;
}

/* ── 1: schema v6 migration matrix ──────────────────────────────────── */

static int test_migration(void) {
    fixture_t fx;
    CHECK(fx_open(&fx) == 0, "fixture"); OK();

    uint32_t ver = 0;
    /* fresh 0 → 6 (runs the S5 stage internally) */
    CHECK(nodus_witness_db_migrate_v2s6(fx.w) == 0, "0->6");
    CHECK(nodus_witness_db_schema_version(fx.w, &ver) == 0 && ver == 6,
          "version 6");
    OK();
    /* idempotent */
    CHECK(nodus_witness_db_migrate_v2s6(fx.w) == 0, "re-run 6"); OK();
    /* unknown version fails closed (both migrations + engine) */
    CHECK(run_sql(fx.w->db, "PRAGMA user_version = 7") == 0, "set 7");
    CHECK(nodus_witness_db_migrate_v2s6(fx.w) == -1, "7 refuses");
    CHECK(run_sql(fx.w->db, "PRAGMA user_version = 6") == 0, "restore");
    OK();
    fx_close(&fx);

    /* 5 → 6 with per-stage fault rollback: digest identical, version 5 */
    fixture_t f5;
    CHECK(fx_open(&f5) == 0, "fixture 5");
    CHECK(nodus_witness_db_migrate_v2s5(f5.w) == 0, "0->5");
    CHECK(nodus_witness_db_schema_version(f5.w, &ver) == 0 && ver == 5,
          "at 5");
    static const nodus_v2s6_mig_fail_t stages[] = {
        V2S6MIG_FAIL_AFTER_BEGIN, V2S6MIG_FAIL_AFTER_TABLES,
        V2S6MIG_FAIL_AFTER_VERIFY, V2S6MIG_FAIL_BEFORE_COMMIT
    };
    for (size_t i = 0; i < sizeof(stages) / sizeof(stages[0]); i++) {
        uint8_t d0[64], d1[64];
        CHECK(db_state_digest(f5.w, d0) == 0, "digest");
        CHECK(nodus_witness_db_migrate_v2s6_ex(f5.w, stages[i]) == -1,
              "stage fails");
        CHECK(db_state_digest(f5.w, d1) == 0 &&
              memcmp(d0, d1, 64) == 0, "stage rollback digest");
        CHECK(nodus_witness_db_schema_version(f5.w, &ver) == 0 &&
              ver == 5, "still 5");
        OK();
    }
    /* then complete 5 → 6 + restart persistence */
    CHECK(nodus_witness_db_migrate_v2s6(f5.w) == 0, "5->6");
    CHECK(fx_reopen(&f5) == 0, "reopen");
    CHECK(nodus_witness_db_schema_version(f5.w, &ver) == 0 && ver == 6,
          "6 persists");
    OK();
    fx_close(&f5);
    return 0;
}

/* ── 2: absent-distribution genesis fixture ─────────────────────────── */

static int stored_head_root(nodus_witness_t *w, uint32_t dom,
                            uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    char sql[96];
    snprintf(sql, sizeof(sql),
             "SELECT head FROM v2_domain_heads WHERE domain_id=%u", dom);
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    int ret = -1;
    if (rc == SQLITE_ROW &&
        sqlite3_column_bytes(st, 0) == DNA_V2_DOMHEAD_ENC_LEN) {
        memcpy(out, (const uint8_t *)sqlite3_column_blob(st, 0) + 4, 64);
        ret = 0;
    }
    sqlite3_finalize(st);
    return ret;
}

static int absent_genesis(fixture_t *fx, uint8_t out_sys[64],
                          uint8_t out_core[64], uint8_t out_glob[64],
                          uint8_t out_manroot[64]) {
    if (fx_open(fx) != 0) return -1;
    if (nodus_witness_db_migrate_v2s9(fx->w) != 0) return -1;
    uint8_t sys_h[64], core_h[64];
    if (domman_hashes(fx->w, sys_h, core_h) != 0) return -1;
    dna_gman_t m;
    gman_base(&m, 0, sys_h, core_h);        /* pre-genesis supply = 0 */
    uint8_t mbytes[8192];
    size_t mlen = 0;
    if (dna_gman_encode(&m, mbytes, sizeof(mbytes), &mlen) != 0) return -1;
    uint8_t gid[64], chain[32];
    /* O15J L2-F1 — the supply row must EXIST before a V2 genesis is
     * committed; its absence used to SKIP the conservation equation for
     * the life of the chain and now fails closed. This fixture's intent
     * is a ZERO-supply chain, so a row holding 0 expresses exactly what
     * it always meant and the equation genuinely evaluates 0 == 0.
     * -2 == already initialized (nodus_witness_db.c:952). */
    {
        uint8_t zh[64];
        memset(zh, 0, sizeof(zh));
        int sv = nodus_witness_supply_init(fx->w, 0, zh);
        if (sv != 0 && sv != -2) return -1;
    }
    if (commit_genesis_read(fx, mbytes, mlen, gid, chain) != 0) return -1;
    if (nodus_witness_system_root_v2(fx->w, out_sys) != 0) return -1;
    if (nodus_witness_core_root_v2(fx->w, out_core) != 0) return -1;
    if (nodus_witness_global_root_v2(fx->w, out_glob, NULL, NULL, NULL)
        != 0)
        return -1;
    return nodus_witness_manifest_root_v2(fx->w, out_manroot);
}

static int test_absent_fixture(void) {
    fixture_t fa, fb;
    uint8_t sys_a[64], core_a[64], glob_a[64], man_a[64];
    uint8_t sys_b[64], core_b[64], glob_b[64], man_b[64];
    CHECK(absent_genesis(&fa, sys_a, core_a, glob_a, man_a) == 0,
          "absent genesis A");
    OK();

    /* the manifest leg is REAL: != the tagged-empty placeholder, and
     * independently reconstructible from the stored manifest hash */
    uint8_t empty[64];
    CHECK(dna_v2_empty_root(DNA_V2_EMPTY_MANIFEST, empty) == 0, "empty");
    CHECK(memcmp(man_a, empty, 64) != 0, "manifest root is real");
    dna_gman_t stored;
    CHECK(nodus_witness_v2_manifest_load(fa.w, 0, &stored) == 0,
          "manifest load");
    CHECK(stored.dist_present == 0, "absent dist stored");
    uint8_t mh[64], man_rec[64];
    CHECK(dna_gman_hash(&stored, mh) == 0, "stored hash");
    uint8_t mhs[1][64];
    memcpy(mhs[0], mh, 64);
    CHECK(dna_v2_manifest_root((const uint8_t (*)[64])mhs, 1,
                               man_rec) == 0 &&
          memcmp(man_rec, man_a, 64) == 0,
          "manifest root reconstruction");
    OK();

    /* stored SYSTEM head root == live recomputation (commits the real
     * manifest root); per-domain roots live in v2_domain_heads — the
     * global block table carries NO named-domain columns. */
    uint8_t head[64];
    CHECK(stored_head_root(fa.w, DNA_DOMAIN_SYSTEM, head) == 0,
          "head row");
    CHECK(memcmp(head, sys_a, 64) == 0, "stored head == recompute");
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fa.w->db,
              "SELECT COUNT(*) FROM pragma_table_info('v2_blocks') "
              "WHERE name IN ('system_root','core_root')", -1, &st,
              NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW &&
              sqlite3_column_int(st, 0) == 0,
              "v2_blocks must carry no named-domain column");
        sqlite3_finalize(st);
    }
    OK();

    /* no unclaimed value without a distribution (native CORE view) */
    uint64_t unc = 99;
    CHECK(nodus_witness_v2_unclaimed_total(fa.w, DNA_DOMAIN_CORE,
                                           g_native_asset, 64, &unc) == 0
          && unc == 0, "no unclaimed");
    OK();

    /* independent second fixture → byte-identical roots */
    CHECK(absent_genesis(&fb, sys_b, core_b, glob_b, man_b) == 0,
          "absent genesis B");
    CHECK(memcmp(sys_a, sys_b, 64) == 0 &&
          memcmp(core_a, core_b, 64) == 0 &&
          memcmp(glob_a, glob_b, 64) == 0 &&
          memcmp(man_a, man_b, 64) == 0,
          "independent fixture root identity");
    OK();
    fx_close(&fa);
    fx_close(&fb);
    return 0;
}

/* ── 3+4+5+7+8: the present-distribution lifecycle fixture (CORE) ───── */

static int test_dist_lifecycle(void) {
    fixture_t fx;
    uint8_t chain[32], gid[64], mh[64];
    CHECK(fx_open(&fx) == 0, "fixture");
    /* window [2, 6] */
    CHECK(dist_genesis(&fx, 32, 2, 6, "testnet-generic", chain, gid, mh)
              == 0,
          "dist genesis");
    OK();

    /* 3. accounting seeded (committed-identity keys) + reconstruction */
    CHECK(q1(fx.w, "SELECT remaining FROM v2_dist_state") == 32,
          "remaining 32");
    CHECK(q1(fx.w, "SELECT target_domain_id FROM v2_dist_state") == 1,
          "explicit target domain stored");
    CHECK(nodus_witness_v2_supply_check(fx.w) == 0, "supply at genesis");
    dna_gman_t stored;
    CHECK(nodus_witness_v2_manifest_load_by_hash(fx.w, mh, &stored) == 0,
          "load by hash");
    CHECK(memcmp(stored.snapshot_root, g_snapshot_root, 64) == 0,
          "snapshot root committed");
    uint8_t rec[64];
    CHECK(dna_dist_snapshot_root(g_leaf, N_LEAVES, rec) == 0 &&
          memcmp(rec, stored.snapshot_root, 64) == 0,
          "snapshot reconstruction byte-identity");
    uint8_t claims_root[64], empty[64];
    CHECK(nodus_witness_claims_root_v2(fx.w, DNA_DOMAIN_CORE,
                                       claims_root) == 0, "cr");
    CHECK(dna_v2_empty_root(DNA_V2_EMPTY_CLAIMS, empty) == 0 &&
          memcmp(claims_root, empty, 64) == 0, "claims root empty");
    OK();

    /* claims for all three leaves */
    dna_claim_t c0, c1, c2;
    CHECK(make_claim(&c0, 0, chain, mh) == 0, "claim0");
    CHECK(make_claim(&c1, 1, chain, mh) == 0, "claim1");
    CHECK(make_claim(&c2, 2, chain, mh) == 0, "claim2");
    OK();

    /* 5a. EARLY: h=1 < start=2 rejects, digest-proven */
    nodus_v2_block_t b;
    mk_claim_block(&b, 1, gid, &c0, 1);
    CHECK(expect_reject(fx.w, &b, "early claim") == 0, "early"); OK();

    /* h=1 spacer commits (no ops, no claims) — wait: a block with no
     * ops and no claims touches nothing and produces no update, which
     * the engine treats as valid metadata-only linkage */
    mk_claim_block(&b, 1, gid, NULL, 0);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0, "spacer h1"); OK();

    /* 4. h=2: MULTI-claim block [c0, c1] commits */
    uint64_t sys_h_before = q1(fx.w,
        "SELECT domain_height FROM v2_domain_heads WHERE domain_id=0");
    dna_claim_t two[2];
    two[0] = c0; two[1] = c1;
    mk_claim_block(&b, 2, gid, two, 2);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0, "claims h2"); OK();

    /* outputs: deterministic id, amount, owner, EXPLICIT domain,
     * created_at — created by the CORE runtime hook */
    for (int i = 0; i < 2; i++) {
        uint8_t nul[64], oid[64];
        CHECK(claim_ids(i == 0 ? &c0 : &c1, DNA_DOMAIN_CORE,
                        g_native_asset, 64, nul, oid) == 0, "ids");
        uint64_t amt = 0, dom = 9, cat = 9;
        char owner[130];
        CHECK(utxo_row(fx.w, oid, &amt, &dom, &cat, owner) == 0,
              "claim utxo exists");
        CHECK(amt == g_conv_amount[i], "converted amount");
        CHECK(dom == 1, "CORE runtime wrote ITS OWN domain id");
        CHECK(cat == 0, "created_at pinned 0");
        /* owner == 128-hex dest binding */
        char want[130];
        static const char hexd[] = "0123456789abcdef";
        for (int k = 0; k < 64; k++) {
            want[k * 2] = hexd[g_leaf[i].dest_binding[k] >> 4];
            want[k * 2 + 1] = hexd[g_leaf[i].dest_binding[k] & 0x0f];
        }
        want[128] = 0;
        CHECK(strcmp(owner, want) == 0, "owner is dest fingerprint");
        OK();
    }
    /* accounting: moved, not minted */
    CHECK(q1(fx.w, "SELECT remaining FROM v2_dist_state") == 32 - 22,
          "remaining 10");
    CHECK(q1(fx.w, "SELECT genesis_supply FROM supply_tracking") == 1000 &&
          q1(fx.w, "SELECT total_minted FROM supply_tracking") == 0 &&
          q1(fx.w, "SELECT total_burned FROM supply_tracking") == 0,
          "supply_tracking untouched — claim never mints");
    CHECK(nodus_witness_v2_supply_check(fx.w) == 0, "supply after claims");
    /* one-owner arithmetic: 968 + 15 + 7 UTXO, 10 unclaimed */
    CHECK(q1(fx.w, "SELECT COALESCE(SUM(amount),0) FROM utxo_set")
              == 968 + 15 + 7, "utxo sum");
    OK();
    /* SYSTEM did not advance; CORE did */
    CHECK(q1(fx.w, "SELECT domain_height FROM v2_domain_heads WHERE "
                   "domain_id=0") == sys_h_before, "SYSTEM unmoved");
    CHECK(q1(fx.w, "SELECT domain_height FROM v2_domain_heads WHERE "
                   "domain_id=1") >= 1, "CORE advanced");
    OK();
    /* claims_root reconstruction from first principles */
    {
        dna_claims_entry_t e[2];
        memset(e, 0, sizeof(e));
        uint8_t nul0[64], nul1[64], oid[64];
        CHECK(claim_ids(&c0, DNA_DOMAIN_CORE, g_native_asset, 64,
                        nul0, oid) == 0, "n0");
        CHECK(claim_ids(&c1, DNA_DOMAIN_CORE, g_native_asset, 64,
                        nul1, oid) == 0, "n1");
        int first = memcmp(nul0, nul1, 64) < 0 ? 0 : 1;
        for (int k = 0; k < 2; k++) {
            const uint8_t *nul = (k == 0) == (first == 0) ? nul0 : nul1;
            int leaf = (k == 0) == (first == 0) ? 0 : 1;
            memcpy(e[k].nullifier, nul, 64);
            memcpy(e[k].manifest_hash, mh, 64);
            e[k].target_domain_id = DNA_DOMAIN_CORE;
            e[k].leaf_index = (uint64_t)leaf;
            e[k].amount = g_conv_amount[leaf];
            e[k].claimed_height = 2;
        }
        uint8_t want[64], got[64];
        CHECK(dna_claims_root(e, 2, want) == 0, "root calc");
        CHECK(nodus_witness_claims_root_v2(fx.w, DNA_DOMAIN_CORE, got)
                  == 0 &&
              memcmp(want, got, 64) == 0,
              "claims_root reconstruction byte-identity");
        OK();
    }

    /* 5b. adversarial matrix at h=3 (every one digest-proven no-op) */
    {
        nodus_v2_block_t bb;
        dna_claim_t x;

        /* duplicate claim within one block */
        dna_claim_t dup[2];
        dup[0] = c2; dup[1] = c2;
        mk_claim_block(&bb, 3, gid, dup, 2);
        CHECK(expect_reject(fx.w, &bb, "dup in block") == 0, "dup"); OK();

        /* already committed claim */
        mk_claim_block(&bb, 3, gid, &c0, 1);
        CHECK(expect_reject(fx.w, &bb, "already claimed") == 0, "spent");
        OK();

        /* destination substitution: leaf data with a FOREIGN dest —
         * Merkle proof cannot validate */
        x = c2;
        memcpy(x.dest_binding, g_leaf[0].dest_binding, 64);
        memcpy(x.pubkey, g_pk[0], QGP_DSA87_PUBLICKEYBYTES);
        {
            uint8_t pre[DNA_CLAIM_PREIMAGE_MAX];
            size_t pl = 0, sl = 0;
            CHECK(dna_claim_preimage(&x, pre, &pl) == 0, "pre");
            CHECK(qgp_dsa87_sign(x.signature, &sl, pre, pl, g_sk[0]) == 0,
                  "sign");
        }
        mk_claim_block(&bb, 3, gid, &x, 1);
        CHECK(expect_reject(fx.w, &bb, "dest substitution") == 0,
              "substitution");
        OK();

        /* right leaf, WRONG key (key does not hash to dest_binding) */
        x = c2;
        memcpy(x.pubkey, g_pk[0], QGP_DSA87_PUBLICKEYBYTES);
        {
            uint8_t pre[DNA_CLAIM_PREIMAGE_MAX];
            size_t pl = 0, sl = 0;
            CHECK(dna_claim_preimage(&x, pre, &pl) == 0, "pre");
            CHECK(qgp_dsa87_sign(x.signature, &sl, pre, pl, g_sk[0]) == 0,
                  "sign");
        }
        mk_claim_block(&bb, 3, gid, &x, 1);
        CHECK(expect_reject(fx.w, &bb, "foreign key") == 0, "wrong key");
        OK();

        /* tampered signature */
        x = c2;
        x.signature[100] ^= 1;
        mk_claim_block(&bb, 3, gid, &x, 1);
        CHECK(expect_reject(fx.w, &bb, "bad sig") == 0, "bad sig"); OK();

        /* wrong amount (conversion/leaf mismatch) */
        x = c2;
        x.source_amount += 1;
        mk_claim_block(&bb, 3, gid, &x, 1);
        CHECK(expect_reject(fx.w, &bb, "wrong amount") == 0, "amount");
        OK();

        /* corrupted Merkle path */
        x = c2;
        x.siblings[0][0] ^= 1;
        mk_claim_block(&bb, 3, gid, &x, 1);
        CHECK(expect_reject(fx.w, &bb, "bad path") == 0, "path"); OK();

        /* wrong index */
        x = c2;
        x.leaf_index = 0;
        mk_claim_block(&bb, 3, gid, &x, 1);
        CHECK(expect_reject(fx.w, &bb, "wrong index") == 0, "index"); OK();

        /* out-of-range index */
        x = c2;
        x.leaf_index = N_LEAVES;
        mk_claim_block(&bb, 3, gid, &x, 1);
        CHECK(expect_reject(fx.w, &bb, "index range") == 0, "range"); OK();

        /* unknown manifest hash (the committed identity) */
        x = c2;
        x.manifest_hash[0] ^= 1;
        mk_claim_block(&bb, 3, gid, &x, 1);
        CHECK(expect_reject(fx.w, &bb, "unknown manifest") == 0,
              "manifest");
        OK();

        /* wrong chain id (cross-chain replay, synthetic) */
        x = c2;
        memset(x.chain_id, 0xFF, 32);
        mk_claim_block(&bb, 3, gid, &x, 1);
        CHECK(expect_reject(fx.w, &bb, "wrong chain") == 0, "chain"); OK();
    }

    /* 7. fault injection at the three S6 stages + F13 with a claim */
    {
        nodus_v2_block_t bb;
        static const nodus_v2_apply_fail_t pts[] = {
            V2AP_FAIL_AFTER_CLAIM_OUTPUT, V2AP_FAIL_AFTER_CLAIM_SPEND,
            V2AP_FAIL_AFTER_CLAIM_STATE, V2AP_FAIL_BEFORE_COMMIT
        };
        for (size_t i = 0; i < sizeof(pts) / sizeof(pts[0]); i++) {
            mk_claim_block(&bb, 3, gid, &c2, 1);
            bb.fail_at = pts[i];
            bb.fail_claim_index = 0;
            CHECK(expect_reject(fx.w, &bb, "fault point") == 0,
                  "fault rollback");
            OK();
        }
    }

    /* 8. restart: state persists; already-spent still rejects;
     * committed block replay is idempotent */
    {
        uint8_t cr_before[64], cr_after[64];
        CHECK(nodus_witness_claims_root_v2(fx.w, DNA_DOMAIN_CORE,
                                           cr_before) == 0, "cr");
        CHECK(fx_reopen(&fx) == 0, "reopen");
        CHECK(nodus_witness_claims_root_v2(fx.w, DNA_DOMAIN_CORE,
                                           cr_after) == 0 &&
              memcmp(cr_before, cr_after, 64) == 0,
              "claims_root persists");
        CHECK(q1(fx.w, "SELECT remaining FROM v2_dist_state") == 10,
              "remaining persists");
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_claims_spent") == 2,
              "spent persists");
        CHECK(nodus_witness_v2_supply_check(fx.w) == 0,
              "supply after restart");
        OK();
        /* re-claim after restart rejects */
        nodus_v2_block_t bb;
        mk_claim_block(&bb, 3, gid, &c0, 1);
        CHECK(expect_reject(fx.w, &bb, "spent after restart") == 0,
              "spent restart");
        OK();
        /* idempotent replay of the committed h=2 block — O14 D6: the
         * no-write path is follower mode, so assert the derived id. */
        dna_claim_t two2[2];
        two2[0] = c0; two2[1] = c1;
        uint8_t id2[64];
        CHECK(v2x_block_id_at(fx.w, 2, id2) == 0, "read committed id2");
        mk_claim_block(&bb, 2, gid, two2, 2);
        bb.expect_block_id = id2;
        CHECK(nodus_witness_v2_apply_block(fx.w, &bb) == 1,
              "identical replay rc 1");
        OK();
    }

    /* 5c. LATE: advance past the window, then claim2 rejects and the
     * remaining value is RETAINED (post-deadline v1 policy — any other
     * disposition is an OPEN future versioned mode) */
    {
        nodus_v2_block_t bb;
        for (uint64_t h = 3; h <= 6; h++) {
            mk_claim_block(&bb, h, gid, NULL, 0);
            CHECK(nodus_witness_v2_apply_block(fx.w, &bb) == 0, "spacer");
        }
        mk_claim_block(&bb, 7, gid, &c2, 1);
        CHECK(expect_reject(fx.w, &bb, "late claim") == 0, "late");
        CHECK(q1(fx.w, "SELECT remaining FROM v2_dist_state") == 10,
              "RETAIN keeps remaining");
        CHECK(nodus_witness_v2_supply_check(fx.w) == 0, "supply late");
        OK();
    }
    fx_close(&fx);
    return 0;
}

/* ── 6: insertion-order independence (twin fixtures) ────────────────── */

static int test_order_independence(void) {
    fixture_t fa, fb;
    uint8_t chA[32], gidA[64], mhA[64], chB[32], gidB[64], mhB[64];
    CHECK(fx_open(&fa) == 0 && fx_open(&fb) == 0, "fixtures");
    CHECK(dist_genesis(&fa, 32, 1, 9, "testnet-generic", chA, gidA, mhA)
              == 0, "genesis A");
    CHECK(dist_genesis(&fb, 32, 1, 9, "testnet-generic", chB, gidB, mhB)
              == 0, "genesis B");
    /* twins: identical manifests ⇒ identical genesis id + chain id */
    CHECK(memcmp(chA, chB, 32) == 0 && memcmp(gidA, gidB, 64) == 0 &&
          memcmp(mhA, mhB, 64) == 0, "twin chains identical");
    OK();

    dna_claim_t c0, c1;
    CHECK(make_claim(&c0, 0, chA, mhA) == 0, "c0");
    CHECK(make_claim(&c1, 1, chA, mhA) == 0, "c1");

    nodus_v2_block_t b;
    dna_claim_t fwd[2], rev[2];
    fwd[0] = c0; fwd[1] = c1;
    rev[0] = c1; rev[1] = c0;
    mk_claim_block(&b, 1, gidA, fwd, 2);
    CHECK(nodus_witness_v2_apply_block(fa.w, &b) == 0, "A applies fwd");
    mk_claim_block(&b, 1, gidB, rev, 2);
    CHECK(nodus_witness_v2_apply_block(fb.w, &b) == 0, "B applies rev");
    OK();

    uint8_t ra[64], rb[64], ca[64], cb[64], ga[64], gb[64];
    CHECK(nodus_witness_claims_root_v2(fa.w, DNA_DOMAIN_CORE, ra) == 0 &&
          nodus_witness_claims_root_v2(fb.w, DNA_DOMAIN_CORE, rb) == 0 &&
          memcmp(ra, rb, 64) == 0,
          "claims_root insertion-order independent");
    CHECK(nodus_witness_core_root_v2(fa.w, ca) == 0 &&
          nodus_witness_core_root_v2(fb.w, cb) == 0 &&
          memcmp(ca, cb, 64) == 0, "core root order independent");
    CHECK(nodus_witness_global_root_v2(fa.w, ga, NULL, NULL, NULL) == 0 &&
          nodus_witness_global_root_v2(fb.w, gb, NULL, NULL, NULL) == 0 &&
          memcmp(ga, gb, 64) == 0, "global root order independent");
    OK();

    /* ── O15A obligation 4: THE BINDING DIRECTION ─────────────────────
     * Everything above proves the roots are STABLE — twins agree, order
     * does not matter. That is only half the property, and on its own it
     * is satisfied by a root that ignores claims entirely.
     *
     * A block carries claims in their OWN array; they never enter
     * tx_root (only envelopes do). Their sole path to the block identity
     * is claims_root -> the target domain's state root -> domains_root ->
     * global_state_root -> BlockID. So the claim set MUST move the
     * global root, or claims would be carried by a block whose identity
     * does not depend on them at all.
     *
     * Compared against a third fixture that applied NO claims. */
    {
        fixture_t fc;
        uint8_t chC[32], gidC[64], mhC[64];
        CHECK(fx_open(&fc) == 0, "fixture C");
        CHECK(dist_genesis(&fc, 32, 1, 9, "testnet-generic", chC, gidC,
                           mhC) == 0, "genesis C");
        /* C is the SAME twin chain — identical genesis, identical
         * manifest — so any root difference below can ONLY come from the
         * claims A applied and C did not. */
        CHECK(memcmp(chA, chC, 32) == 0 && memcmp(gidA, gidC, 64) == 0,
              "C is a twin of A");

        uint8_t rc_[64], cc_[64], gc[64];
        CHECK(nodus_witness_claims_root_v2(fc.w, DNA_DOMAIN_CORE, rc_) == 0,
              "C claims_root");
        CHECK(memcmp(ra, rc_, 64) != 0,
              "CLAIMS DO NOT REACH claims_root — a claimed and an "
              "unclaimed twin share a root");
        CHECK(nodus_witness_core_root_v2(fc.w, cc_) == 0 &&
              memcmp(ca, cc_, 64) != 0,
              "claims do not reach the CORE state root");
        CHECK(nodus_witness_global_root_v2(fc.w, gc, NULL, NULL, NULL) == 0 &&
              memcmp(ga, gc, 64) != 0,
              "claims do not reach the GLOBAL state root — a block's "
              "identity would not depend on its own claims");
        OK();
        fx_close(&fc);
    }
    fx_close(&fa);
    fx_close(&fb);
    return 0;
}

/* ── 9: never-mint — manifest committing less than the snapshot sum ─── */

static int test_never_mint(void) {
    fixture_t fx;
    uint8_t chain[32], gid[64], mh[64];
    CHECK(fx_open(&fx) == 0, "fixture");
    /* total_claimable 20 < Σ converted 32: the distribution is the ONLY
     * source; once drained, further structurally-valid claims REJECT */
    CHECK(dist_genesis(&fx, 20, 1, 9, "testnet-generic", chain, gid, mh)
              == 0, "genesis 20");
    OK();
    dna_claim_t c0, c1;
    CHECK(make_claim(&c0, 0, chain, mh) == 0, "c0");
    CHECK(make_claim(&c1, 1, chain, mh) == 0, "c1");
    nodus_v2_block_t b;
    mk_claim_block(&b, 1, gid, &c0, 1);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0, "claim 15 of 20");
    CHECK(q1(fx.w, "SELECT remaining FROM v2_dist_state") == 5,
          "remaining 5");
    OK();
    /* c1 needs 7 > 5 — MUST reject (a claim can never mint) */
    mk_claim_block(&b, 2, gid, &c1, 1);
    CHECK(expect_reject(fx.w, &b, "overdraw") == 0, "never mints");
    CHECK(nodus_witness_v2_supply_check(fx.w) == 0, "supply intact");
    OK();
    fx_close(&fx);
    return 0;
}

/* ── 10: genesis manifest rejects (whole genesis rolled back) ───────── */

static int genesis_expect_fail(dna_gman_t *m, int seed, const char *msg) {
    fixture_t fx;
    if (fx_open(&fx) != 0) return 1;
    if (nodus_witness_db_migrate_v2s9(fx.w) != 0) { fx_close(&fx); return 1; }
    if (seed && seed_supply(fx.w, 1000, 968) != 0) { fx_close(&fx); return 1; }
    uint8_t sys_h[64], core_h[64];
    if (domman_hashes(fx.w, sys_h, core_h) != 0) { fx_close(&fx); return 1; }
    /* the caller pre-filled everything EXCEPT the real hashes; slot
     * them in unless the test wants them wrong (all-0xEE marker) */
    if (m->domains[0].manifest_hash[0] != 0xEE)
        memcpy(m->domains[0].manifest_hash, sys_h, 64);
    if (m->domain_count > 1 && m->domains[1].manifest_hash[0] != 0xEE)
        memcpy(m->domains[1].manifest_hash, core_h, 64);

    uint8_t mbytes[8192];
    size_t mlen = 0;
    if (dna_gman_encode(m, mbytes, sizeof(mbytes), &mlen) != 0) {
        fx_close(&fx);
        return 1;
    }
    uint8_t vset[64];
    memset(vset, 0x77, 64);
    /* O14: assertion omitted — this genesis must be rejected on its own
     * (lying) manifest, not because an id failed to match. */
    uint8_t d0[64], d1[64];
    if (db_state_digest(fx.w, d0) != 0) { fx_close(&fx); return 1; }
    if (nodus_witness_v2_genesis_ex(fx.w, NULL, vset, 0, mbytes, mlen)
        != -1) {
        fprintf(stderr, "genesis should fail: %s\n", msg);
        fx_close(&fx);
        return 1;
    }
    if (db_state_digest(fx.w, d1) != 0 || memcmp(d0, d1, 64) != 0) {
        fprintf(stderr, "genesis reject not rolled back: %s\n", msg);
        fx_close(&fx);
        return 1;
    }
    fx_close(&fx);
    return 0;
}

static int test_genesis_rejects(void) {
    dna_gman_t m;
    uint8_t zero[64];
    memset(zero, 0, sizeof(zero));

    /* wrong DomainManifest hash (registry cross-check) */
    gman_base(&m, 1000, zero, zero);
    gman_dist(&m, 32, 1, 9, "testnet-generic", DNA_DOMAIN_CORE,
              g_native_asset, 64);
    memset(m.domains[1].manifest_hash, 0xEE, 64);   /* wrong-marker */
    CHECK(genesis_expect_fail(&m, 1, "wrong domman hash") == 0,
          "hash mismatch rejects");
    OK();

    /* wrong domain count (SYSTEM only, registry has 2) */
    gman_base(&m, 1000, zero, zero);
    m.domain_count = 1;
    gman_dist(&m, 32, 1, 9, "testnet-generic", DNA_DOMAIN_SYSTEM,
              g_native_asset, 64);
    CHECK(genesis_expect_fail(&m, 1, "wrong count") == 0,
          "count mismatch rejects");
    OK();

    /* genesis-supply mismatch against supply_tracking */
    gman_base(&m, 999, zero, zero);
    gman_dist(&m, 32, 1, 9, "testnet-generic", DNA_DOMAIN_CORE,
              g_native_asset, 64);
    CHECK(genesis_expect_fail(&m, 1, "supply mismatch") == 0,
          "supply mismatch rejects");
    OK();

    /* UNREGISTERED target domain: fails closed — the engine never
     * "defaults" an unknown target anywhere */
    gman_base(&m, 1000, zero, zero);
    gman_dist(&m, 32, 1, 9, "testnet-generic", 42, g_native_asset, 64);
    CHECK(genesis_expect_fail(&m, 1, "unknown target domain") == 0,
          "unregistered target rejects");
    OK();

    /* target SYSTEM: registered and ACTIVE, but its runtime carries NO
     * claim hooks — a runtime that cannot apply claims cannot be a
     * distribution target */
    gman_base(&m, 1000, zero, zero);
    gman_dist(&m, 32, 1, 9, "testnet-generic", DNA_DOMAIN_SYSTEM,
              g_native_asset, 64);
    CHECK(genesis_expect_fail(&m, 1, "target without claim hooks") == 0,
          "hookless target rejects");
    OK();

    /* asset the CORE runtime refuses (non-native token id) */
    gman_base(&m, 1000, zero, zero);
    {
        uint8_t alien[64];
        memset(alien, 0x5A, 64);
        gman_dist(&m, 32, 1, 9, "testnet-generic", DNA_DOMAIN_CORE,
                  alien, 64);
    }
    CHECK(genesis_expect_fail(&m, 1, "asset refused by runtime") == 0,
          "incompatible asset rejects");
    OK();
    return 0;
}

/* ── 11: inactive boundary — no live admission for types 12-14 ──────── */

static int test_inactive_boundary(void) {
    fixture_t fx;
    uint8_t chain[32], gid[64], mh[64];
    CHECK(fx_open(&fx) == 0, "fixture");
    CHECK(dist_genesis(&fx, 32, 1, 9, "testnet-generic", chain, gid, mh)
              == 0, "genesis");
    for (uint8_t ty = 12; ty <= 14; ty++) {
        for (uint32_t dom = 0; dom <= 1; dom++) {
            dna_exec_context_t ctx;
            CHECK(dna_exec_context_init(&ctx, chain, dom, DNA_POOL_NONE,
                                        ty, 3, 1, 0) == 0, "ctx");
            CHECK(nodus_witness_domreg_admit_v2(fx.w, chain, &ctx, 0, 0,
                                                NULL) == -1,
                  "types 12-14 stay inert");
        }
    }
    OK();
    fx_close(&fx);
    return 0;
}

/* ── 12: GENERICITY — a distribution targeting synthetic domain T3 ──── */

/* T3 fixture: registry = SYSTEM + CORE + T3 (T3 registered through the
 * GENERIC registration path before genesis); the genesis manifest lists
 * all three domains and its distribution EXPLICITLY targets T3 with the
 * T3-only asset. Supply: the chain's native 1000 all stays in CORE
 * UTXOs — the T3-asset claimable 32 is NOT DNAC and MUST NOT enter the
 * DNAC equation. */
static int t3_genesis(fixture_t *fx, uint8_t out_chain[32],
                      uint8_t out_gid[64], uint8_t out_mh[64],
                      uint64_t start_h, uint64_t end_h) {
    if (fx_open(fx) != 0) return -1;
    fx->w->v2_runtime_table = g_ext_table;
    fx->w->v2_runtime_table_n = g_ext_n;
    if (nodus_witness_db_migrate_v2s9(fx->w) != 0) return -1;
    if (run_sql(fx->w->db,
            "CREATE TABLE t3_state (id BLOB PRIMARY KEY, "
            "amount INTEGER NOT NULL, asset BLOB NOT NULL)") != 0)
        return -1;
    if (seed_supply(fx->w, 1000, 1000) != 0) return -1;
    uint8_t sys_h[64], core_h[64], t3_h[64];
    if (domman_hashes(fx->w, sys_h, core_h) != 0) return -1;
    if (register_synthetic(fx->w, &g_ext_table[2]) != 0) return -1;
    if (domman_hash_of(fx->w, T3_DOMAIN, t3_h) != 0) return -1;

    dna_gman_t m;
    gman_base(&m, 1000, sys_h, core_h);
    m.domain_count = 3;
    m.domains[2].domain_id = T3_DOMAIN;
    memcpy(m.domains[2].manifest_hash, t3_h, 64);
    gman_dist(&m, 32, start_h, end_h, "t3-generic", T3_DOMAIN,
              T3_ASSET, 5);
    uint8_t mbytes[8192];
    size_t mlen = 0;
    if (dna_gman_encode(&m, mbytes, sizeof(mbytes), &mlen) != 0) return -1;
    if (dna_gman_hash(&m, out_mh) != 0) return -1;
    return commit_genesis_read(fx, mbytes, mlen, out_gid, out_chain);
}

static int test_generic_t3(void) {
    fixture_t fx;
    uint8_t chain[32], gid[64], mh[64];
    g_t3_claim_hook_calls = 0;
    g_t3_invariant_calls = 0;
    CHECK(t3_genesis(&fx, chain, gid, mh, 1, 9) == 0, "t3 genesis"); OK();

    /* three registered domains → three genesis heads; the schema, the
     * header codec and the block table needed NOTHING new */
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_domain_heads") == 3,
          "three domain heads");
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_dist_state") == 1 &&
          q1(fx.w, "SELECT target_domain_id FROM v2_dist_state")
              == T3_DOMAIN,
          "distribution EXPLICITLY targets T3");
    OK();

    /* the DNAC equation balances with the T3 allocation OUTSIDE it:
     * native 1000 == 1000 UTXO; the 32 T3-asset units are NOT summed */
    CHECK(nodus_witness_v2_supply_check(fx.w) == 0,
          "T3 asset never summed into the DNAC equation");
    CHECK(g_t3_invariant_calls > 0,
          "invariant dispatch reached the T3 runtime");
    uint64_t unc = 0;
    CHECK(nodus_witness_v2_unclaimed_total(fx.w, DNA_DOMAIN_CORE,
                                           g_native_asset, 64, &unc) == 0
          && unc == 0, "no CORE-native unclaimed");
    CHECK(nodus_witness_v2_unclaimed_total(fx.w, T3_DOMAIN, T3_ASSET, 5,
                                           &unc) == 0 && unc == 32,
          "T3 unclaimed = 32");
    OK();

    /* nullifiers cannot collide across domains/assets: same leaf, same
     * chain — different committed target ⇒ different nullifier */
    dna_claim_t c0;
    CHECK(make_claim(&c0, 0, chain, mh) == 0, "t3 claim0");
    {
        uint8_t n_t3[64], n_core[64], oid[64];
        CHECK(claim_ids(&c0, T3_DOMAIN, T3_ASSET, 5, n_t3, oid) == 0,
              "t3 nul");
        CHECK(claim_ids(&c0, DNA_DOMAIN_CORE, g_native_asset, 64,
                        n_core, oid) == 0, "core nul");
        CHECK(memcmp(n_t3, n_core, 64) != 0,
              "cross-domain nullifiers cannot collide");
        OK();
    }

    /* the claim routes through T3's REGISTERED hook, creates T3's OWN
     * output, and leaves utxo_set (CORE state) COMPLETELY untouched —
     * no generic path applies a default domain */
    uint64_t utxo_rows_before =
        q1(fx.w, "SELECT COUNT(*) FROM utxo_set");
    uint64_t core_h_before = q1(fx.w,
        "SELECT domain_height FROM v2_domain_heads WHERE domain_id=1");
    uint8_t core_root_before[64];
    CHECK(nodus_witness_core_root_v2(fx.w, core_root_before) == 0,
          "core root");
    nodus_v2_block_t b;
    mk_claim_block(&b, 1, gid, &c0, 1);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0, "t3 claim block");
    OK();
    CHECK(g_t3_claim_hook_calls == 1,
          "claim application reached the T3 runtime hook");
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM t3_state") == 1,
          "T3 domain-local output exists");
    CHECK(q1(fx.w, "SELECT amount FROM t3_state") == g_conv_amount[0],
          "T3 output amount");
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM utxo_set") == utxo_rows_before,
          "NO utxo_set row created — no default domain");
    CHECK(q1(fx.w, "SELECT domain_height FROM v2_domain_heads WHERE "
                   "domain_id=1") == core_h_before, "CORE unmoved");
    CHECK(q1(fx.w, "SELECT domain_height FROM v2_domain_heads WHERE "
                   "domain_id=7") == 1, "T3 advanced");
    {
        uint8_t core_root_after[64];
        CHECK(nodus_witness_core_root_v2(fx.w, core_root_after) == 0 &&
              memcmp(core_root_before, core_root_after, 64) == 0,
              "CORE state root unchanged by a T3 claim");
    }
    CHECK(q1(fx.w, "SELECT remaining FROM v2_dist_state") == 32 - 15,
          "T3 remaining decremented");
    CHECK(nodus_witness_v2_supply_check(fx.w) == 0, "supply after claim");
    OK();

    /* per-domain claims_root ownership: the claim sits in T3's root,
     * NOT in CORE's */
    {
        uint8_t cr_core[64], cr_t3[64], empty[64];
        CHECK(nodus_witness_claims_root_v2(fx.w, DNA_DOMAIN_CORE,
                                           cr_core) == 0 &&
              nodus_witness_claims_root_v2(fx.w, T3_DOMAIN, cr_t3) == 0,
              "roots");
        CHECK(dna_v2_empty_root(DNA_V2_EMPTY_CLAIMS, empty) == 0, "e");
        CHECK(memcmp(cr_core, empty, 64) == 0,
              "CORE claims root stays empty");
        CHECK(memcmp(cr_t3, empty, 64) != 0, "T3 claims root is real");
        OK();
    }

    /* cross-manifest replay: the T3-signed claim presented under a
     * DIFFERENT committed manifest hash rejects (signature binds the
     * manifest identity, which commits target domain + asset) */
    {
        dna_claim_t x = c0;
        x.manifest_hash[5] ^= 1;
        nodus_v2_block_t bb;
        mk_claim_block(&bb, 2, gid, &x, 1);
        CHECK(expect_reject(fx.w, &bb, "cross-manifest replay") == 0,
              "cross-manifest replay rejects");
        OK();
    }

    /* SIDECAR: a block carrying a claim CANNOT slip past a follower's
     * root expectation — the claim's state effect lands in the
     * committed global root or the block rejects atomically */
    {
        dna_claim_t c1;
        CHECK(make_claim(&c1, 1, chain, mh) == 0, "claim1");
        uint8_t stale_root[64];
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "SELECT global_root FROM v2_blocks WHERE global_height=1",
              -1, &st, NULL) == SQLITE_OK &&
              sqlite3_step(st) == SQLITE_ROW &&
              sqlite3_column_bytes(st, 0) == 64, "stale root");
        memcpy(stale_root, sqlite3_column_blob(st, 0), 64);
        sqlite3_finalize(st);
        nodus_v2_block_t bb;
        mk_claim_block(&bb, 2, gid, &c1, 1);
        bb.expect_global_root = stale_root;   /* claim-less expectation */
        CHECK(expect_reject(fx.w, &bb,
                            "sidecar claim vs root expectation") == 0,
              "uncommitted sidecar claim cannot affect state");
        OK();
    }

    /* SYSTEM + CORE + T3 block fault → the COMPLETE block rolls back */
    {
        dna_claim_t c1;
        CHECK(make_claim(&c1, 1, chain, mh) == 0, "claim1");
        static v2x_env_t e3s, e3c;
        {
            uint8_t skey[12];
            v2x_put32(skey, 2);
            v2x_put64(skey + 4, 999991);
            uint8_t sval[8];
            v2x_put64(sval, 5);
            CHECK(v2x_env1(&e3s, 0, 1, V2X_OP_CC, DNA_EFFECT_CREATE,
                           DNA_EFFECT_PRE_ABSENT, skey, 12, sval, 8)
                      == 0, "e3s");
            uint8_t ckey[64] = { 0 };
            ckey[63] = 0x71;
            uint8_t cval[8] = { 0 };     /* amount 0: supply-silent      */
            CHECK(v2x_env1(&e3c, 1, 1, V2X_OP_UTXO, DNA_EFFECT_CREATE,
                           DNA_EFFECT_PRE_ABSENT, ckey, 64, cval, 8)
                      == 0, "e3c");
        }
        nodus_v2_envelope_t v3d[2] = {
            { e3s.bytes, e3s.len }, { e3c.bytes, e3c.len }
        };
        nodus_v2_block_t bb;
        mk_claim_block(&bb, 2, gid, &c1, 1);
        bb.envs = v3d;
        bb.n_envs = 2;
        bb.fail_at = V2AP_FAIL_BEFORE_COMMIT;
        CHECK(expect_reject(fx.w, &bb, "3-domain fault") == 0,
              "SYSTEM+CORE+T3 fault rolls the whole block back");
        OK();
    }

    /* restart: T3 state + spent set survive; re-claim rejects */
    {
        CHECK(fx_reopen(&fx) == 0, "reopen");
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM t3_state") == 1,
              "T3 state persists");
        nodus_v2_block_t bb;
        mk_claim_block(&bb, 2, gid, &c0, 1);
        CHECK(expect_reject(fx.w, &bb, "spent after restart") == 0,
              "T3 spent persists");
        OK();
    }
    fx_close(&fx);
    return 0;
}

/* Unknown/inactive target RUNTIME at claim time: same fixture but the
 * witness (e.g. after a restart with different software) no longer
 * carries the T3 runtime — the claim must fail closed. */
static int test_generic_unresolvable_target(void) {
    fixture_t fx;
    uint8_t chain[32], gid[64], mh[64];
    CHECK(t3_genesis(&fx, chain, gid, mh, 1, 9) == 0, "t3 genesis"); OK();

    dna_claim_t c0;
    CHECK(make_claim(&c0, 0, chain, mh) == 0, "claim0");

    /* drop the T3 runtime: only the two production natives remain */
    fx.w->v2_runtime_table = g_ext_table;
    fx.w->v2_runtime_table_n = 2;
    nodus_v2_block_t b;
    mk_claim_block(&b, 1, gid, &c0, 1);
    /* NOTE: the supply gate ALSO fails closed here (ACTIVE registered
     * domain without a runtime = unknown state), so the reject fires
     * before any state moves — digest-proven. */
    CHECK(expect_reject(fx.w, &b, "unresolvable target runtime") == 0,
          "unknown target runtime rejects");
    OK();

    /* restore, then mark T3 PAUSED in the registry: an INACTIVE target
     * fails closed too */
    fx.w->v2_runtime_table_n = g_ext_n;
    {
        dna_domreg_record_t rec;
        CHECK(nodus_witness_domreg_get(fx.w, T3_DOMAIN, &rec, NULL, NULL)
                  == 0, "rec");
        rec.status = DNA_DOMST_PAUSED;
        uint8_t recb[DNA_DOMREG_REC_ENC_LEN];
        CHECK(dna_domreg_record_encode(&rec, recb) == 0, "enc");
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "UPDATE domain_registry SET record=?1 WHERE domain_id=?2",
              -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, recb, sizeof(recb), SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)T3_DOMAIN);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "update");
        sqlite3_finalize(st);
    }
    mk_claim_block(&b, 1, gid, &c0, 1);
    CHECK(expect_reject(fx.w, &b, "inactive target") == 0,
          "inactive target rejects");
    OK();
    fx_close(&fx);
    return 0;
}

/* ── 13: COEXISTENCE — two synthetic runtimes, one chain ────────────── */

static int test_generic_coexistence(void) {
    fixture_t fx;
    CHECK(fx_open(&fx) == 0, "fixture");
    fx.w->v2_runtime_table = g_ext_table;
    fx.w->v2_runtime_table_n = g_ext_n;
    CHECK(nodus_witness_db_migrate_v2s9(fx.w) == 0, "migrate");
    CHECK(run_sql(fx.w->db,
        "CREATE TABLE t3_state (id BLOB PRIMARY KEY, "
        "amount INTEGER NOT NULL, asset BLOB NOT NULL);"
        "CREATE TABLE t4_state (id BLOB PRIMARY KEY, "
        "amount INTEGER NOT NULL, asset BLOB NOT NULL)") == 0, "tables");
    CHECK(seed_supply(fx.w, 1000, 1000) == 0, "supply");
    uint8_t sys_h[64], core_h[64], t3_h[64], t4_h[64];
    CHECK(domman_hashes(fx.w, sys_h, core_h) == 0, "natives");
    CHECK(register_synthetic(fx.w, &g_ext_table[2]) == 0, "reg T3");
    CHECK(register_synthetic(fx.w, &g_ext_table[3]) == 0, "reg T4");
    CHECK(domman_hash_of(fx.w, T3_DOMAIN, t3_h) == 0, "t3 hash");
    CHECK(domman_hash_of(fx.w, T4_DOMAIN, t4_h) == 0, "t4 hash");

    dna_gman_t m;
    gman_base(&m, 1000, sys_h, core_h);
    m.domain_count = 4;
    m.domains[2].domain_id = T3_DOMAIN;
    memcpy(m.domains[2].manifest_hash, t3_h, 64);
    m.domains[3].domain_id = T4_DOMAIN;
    memcpy(m.domains[3].manifest_hash, t4_h, 64);
    gman_dist(&m, 32, 1, 9, "t3-generic", T3_DOMAIN, T3_ASSET, 5);
    uint8_t mbytes[8192];
    size_t mlen = 0;
    CHECK(dna_gman_encode(&m, mbytes, sizeof(mbytes), &mlen) == 0, "enc");
    uint8_t mh[64];
    CHECK(dna_gman_hash(&m, mh) == 0, "mh");
    uint8_t gid[64], chain[32];
    CHECK(commit_genesis_read(&fx, mbytes, mlen, gid, chain) == 0,
          "4-domain genesis");
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_domain_heads") == 4,
          "four heads, zero header/schema changes");
    OK();

    /* a T3-targeted claim and a T4-touching envelope coexist in one
     * block */
    dna_claim_t c0;
    CHECK(make_claim(&c0, 0, chain, mh) == 0, "claim0");
    static v2x_env_t et4;
    CHECK(env_tn_put(&et4, T4_DOMAIN, 0x01, 5, T4_ASSET) == 0, "et4");
    nodus_v2_block_t b;
    mk_claim_block(&b, 1, gid, &c0, 1);
    nodus_v2_envelope_t vt4 = { et4.bytes, et4.len };
    b.envs = &vt4;
    b.n_envs = 1;
    CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0, "mixed block");
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM t3_state") == 1 &&
          q1(fx.w, "SELECT COUNT(*) FROM t4_state") == 1,
          "both synthetic runtimes drove their own state");
    CHECK(q1(fx.w, "SELECT domain_height FROM v2_domain_heads WHERE "
                   "domain_id=7") == 1 &&
          q1(fx.w, "SELECT domain_height FROM v2_domain_heads WHERE "
                   "domain_id=9") == 1, "both heads advanced");
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_domain_updates WHERE "
                   "global_height=1") == 2, "two updates");
    CHECK(nodus_witness_v2_supply_check(fx.w) == 0, "supply holds");
    OK();
    fx_close(&fx);
    return 0;
}

/* ── 14: canonical DomainHead lifecycle ─────────────────────────────── */

/* Fetch a domain's persisted 89-byte head blob. 0 found / 1 absent. */
static int head_blob(nodus_witness_t *w, uint32_t dom,
                     uint8_t out[DNA_V2_DOMHEAD_ENC_LEN]) {
    sqlite3_stmt *st = NULL;
    char sql[96];
    snprintf(sql, sizeof(sql),
             "SELECT head FROM v2_domain_heads WHERE domain_id=%u", dom);
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    int ret = -1;
    if (rc == SQLITE_ROW &&
        sqlite3_column_bytes(st, 0) == DNA_V2_DOMHEAD_ENC_LEN) {
        memcpy(out, sqlite3_column_blob(st, 0), DNA_V2_DOMHEAD_ENC_LEN);
        ret = 0;
    } else if (rc == SQLITE_DONE) {
        ret = 1;
    }
    sqlite3_finalize(st);
    return ret;
}

static uint64_t be64_at(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

/* Lifecycle genesis: SYSTEM + CORE ACTIVE, T3 REGISTERED-only (present
 * in the registry, ABSENT from committed domain state). */
static int lifecycle_genesis(fixture_t *fx, uint8_t out_gid[64]) {
    if (fx_open(fx) != 0) return -1;
    fx->w->v2_runtime_table = g_ext_table;
    fx->w->v2_runtime_table_n = g_ext_n;
    if (nodus_witness_db_migrate_v2s9(fx->w) != 0) return -1;
    if (run_sql(fx->w->db,
            "CREATE TABLE t3_state (id BLOB PRIMARY KEY, "
            "amount INTEGER NOT NULL, asset BLOB NOT NULL)") != 0)
        return -1;
    if (seed_supply(fx->w, 1000, 1000) != 0) return -1;
    uint8_t sys_h[64], core_h[64], t3_h[64];
    if (domman_hashes(fx->w, sys_h, core_h) != 0) return -1;
    if (register_synthetic_only(fx->w, &g_ext_table[2]) != 0) return -1;
    if (domman_hash_of(fx->w, T3_DOMAIN, t3_h) != 0) return -1;

    dna_gman_t m;
    gman_base(&m, 1000, sys_h, core_h);
    m.domain_count = 3;
    m.domains[2].domain_id = T3_DOMAIN;
    memcpy(m.domains[2].manifest_hash, t3_h, 64);
    uint8_t mbytes[8192];
    size_t mlen = 0;
    if (dna_gman_encode(&m, mbytes, sizeof(mbytes), &mlen) != 0) return -1;
    uint8_t chain[32];
    return commit_genesis_read(fx, mbytes, mlen, out_gid, chain);
}


static int test_lifecycle(void) {
    fixture_t fx;
    uint8_t gid[64];
    CHECK(lifecycle_genesis(&fx, gid) == 0, "lifecycle genesis"); OK();

    /* BEFORE ACTIVATION: registry-only — no head, absent from
     * domains_root, cannot execute. */
    uint8_t blob[DNA_V2_DOMHEAD_ENC_LEN], blob2[DNA_V2_DOMHEAD_ENC_LEN];
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_domain_heads") == 2,
          "registered domain must have NO head before activation");
    CHECK(head_blob(fx.w, T3_DOMAIN, blob) == 1, "T3 head absent"); OK();
    static v2x_env_t et3;
    nodus_v2_block_t b;
    CHECK(env_tn_put(&et3, T3_DOMAIN, 0x01, 5, T3_ASSET) == 0, "et3");
    mk_env_block(&b, 1, gid, &et3);
    CHECK(expect_reject(fx.w, &b, "pre-activation execution") == 0,
          "pre-activation execution rejects"); OK();

    /* restart BEFORE activation reproduces identical roots */
    uint8_t g0[64], g0b[64];
    CHECK(nodus_witness_global_root_v2(fx.w, g0, NULL, NULL, NULL) == 0,
          "g0");
    CHECK(fx_reopen(&fx) == 0, "reopen pre-activation");
    CHECK(nodus_witness_global_root_v2(fx.w, g0b, NULL, NULL, NULL) == 0 &&
          memcmp(g0, g0b, 64) == 0, "pre-activation restart roots"); OK();

    /* ACTIVATION BLOCK: the SYSTEM registry transition + the canonical
     * height-zero head, atomically. First with an injected fault —
     * registry transition, head, roots and metadata ALL roll back. */
    static v2x_env_t eact;
    CHECK(env_status(&eact, fx.w, T3_DOMAIN, DNA_DOMST_ACTIVE, 0) == 0,
          "eact");
    mk_env_block(&b, 1, gid, &eact);
    b.fail_at = V2AP_FAIL_BEFORE_COMMIT;
    CHECK(expect_reject(fx.w, &b, "activation fault") == 0,
          "activation fault rolls back registry+head+roots+meta"); OK();
    mk_env_block(&b, 1, gid, &eact);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0, "activation block");
    OK();

    /* the canonical activation head: EVERY field one exact value */
    {
        dna_domreg_record_t rec;
        dna_domain_manifest_t man;
        CHECK(nodus_witness_domreg_get(fx.w, T3_DOMAIN, &rec, &man, NULL)
                  == 0 && rec.status == DNA_DOMST_ACTIVE,
              "registry transitioned");
        CHECK(head_blob(fx.w, T3_DOMAIN, blob) == 0, "head created");
        CHECK(be64_at(blob + 68) == 0, "domain_height = 0");
        CHECK(be64_at(blob + 76) == 1, "last_updated = activation block");
        CHECK(blob[88] == DNA_DOMST_ACTIVE, "status = ACTIVE");
        /* initial root = the registry-committed genesis_state_root =
         * the runtime's live root (independent recomputation) */
        CHECK(memcmp(blob + 4, man.genesis_state_root, 64) == 0,
              "activation root == committed genesis_state_root");
        uint8_t live[64];
        CHECK(t3_state_root(&g_ext_table[2],
                            (struct nodus_witness *)fx.w, live) == 0 &&
              memcmp(blob + 4, live, 64) == 0,
              "activation root == live runtime recomputation");
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_root_history WHERE "
                       "domain_id=7 AND domain_height=0 AND "
                       "global_height=1") == 1, "height-0 history row");
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_domain_heads") == 3,
              "head entered domains_root set");
        OK();
    }

    /* TWIN NODE: an independent fixture running the same sequence
     * derives a byte-identical activation head and global root. */
    {
        fixture_t ft;
        uint8_t gid2[64];
        CHECK(lifecycle_genesis(&ft, gid2) == 0, "twin genesis");
        CHECK(memcmp(gid, gid2, 64) == 0, "twin chains identical");
        static v2x_env_t eact2;
        static nodus_v2_envelope_t eref2;
        CHECK(env_status(&eact2, ft.w, T3_DOMAIN, DNA_DOMST_ACTIVE, 0)
                  == 0, "twin act env");
        /* twin determinism guard: an identical sequence must build a
         * byte-identical envelope, or the derived ids diverge */
        CHECK(eact2.len == eact.len &&
              memcmp(eact2.bytes, eact.bytes, eact.len) == 0,
              "twin activation envelopes diverged");
        nodus_v2_block_t b2;
        mk_claim_block(&b2, 1, gid2, NULL, 0);
        eref2.env_bytes = eact2.bytes;
        eref2.env_len = eact2.len;
        b2.envs = &eref2;
        b2.n_envs = 1;
        CHECK(nodus_witness_v2_apply_block(ft.w, &b2) == 0, "twin apply");
        uint8_t tb[DNA_V2_DOMHEAD_ENC_LEN];
        CHECK(head_blob(ft.w, T3_DOMAIN, tb) == 0 &&
              memcmp(tb, blob, DNA_V2_DOMHEAD_ENC_LEN) == 0,
              "twin activation heads byte-identical");
        uint8_t ga[64], gb[64];
        CHECK(nodus_witness_global_root_v2(fx.w, ga, NULL, NULL, NULL) == 0
              && nodus_witness_global_root_v2(ft.w, gb, NULL, NULL, NULL)
                     == 0 &&
              memcmp(ga, gb, 64) == 0, "twin global roots identical");
        OK();
        fx_close(&ft);
    }

    /* restart AFTER activation reproduces identical heads + roots */
    {
        uint8_t g1[64], g1b[64];
        CHECK(nodus_witness_global_root_v2(fx.w, g1, NULL, NULL, NULL)
                  == 0, "g1");
        CHECK(fx_reopen(&fx) == 0, "reopen post-activation");
        CHECK(nodus_witness_global_root_v2(fx.w, g1b, NULL, NULL, NULL)
                  == 0 && memcmp(g1, g1b, 64) == 0,
              "post-activation restart roots");
        CHECK(head_blob(fx.w, T3_DOMAIN, blob2) == 0 &&
              memcmp(blob, blob2, DNA_V2_DOMHEAD_ENC_LEN) == 0,
              "head survives restart byte-identically"); OK();
    }

    /* FIRST EXECUTION does not synthesize or replace the head — it
     * advances it through the pinned DomainUpdate rules (0 → 1). */
    mk_env_block(&b, 2, gid, &et3);      /* the pre-activation envelope */
    CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0, "first execution");
    CHECK(head_blob(fx.w, T3_DOMAIN, blob) == 0 &&
          be64_at(blob + 68) == 1 && be64_at(blob + 76) == 2,
          "head advanced 0 -> 1 (no replacement)");
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_root_history WHERE "
                   "domain_id=7") == 2, "history 0 and 1"); OK();

    /* UNTOUCHED ACTIVE: exact head + height retained byte-identically
     * (an empty block touches nothing — still a legal block). */
    mk_env_block(&b, 3, gid, NULL);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0, "spacer");
    CHECK(head_blob(fx.w, T3_DOMAIN, blob2) == 0 &&
          memcmp(blob, blob2, DNA_V2_DOMHEAD_ENC_LEN) == 0,
          "untouched ACTIVE head byte-identical"); OK();

    /* PAUSE: head carried byte-unchanged, no execution, no advance —
     * and carrying it does NOT require the runtime. */
    static v2x_env_t epause;
    CHECK(env_status(&epause, fx.w, T3_DOMAIN, DNA_DOMST_PAUSED, 0) == 0,
          "epause");
    mk_env_block(&b, 4, gid, &epause);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0, "pause block");
    CHECK(head_blob(fx.w, T3_DOMAIN, blob2) == 0 &&
          memcmp(blob, blob2, DNA_V2_DOMHEAD_ENC_LEN) == 0,
          "PAUSED head remains committed unchanged"); OK();
    static v2x_env_t et3b;
    CHECK(env_tn_put(&et3b, T3_DOMAIN, 0x02, 5, T3_ASSET) == 0, "et3b");
    mk_env_block(&b, 5, gid, &et3b);
    CHECK(expect_reject(fx.w, &b, "paused execution") == 0,
          "PAUSED admits no execution"); OK();
    /* runtime withdrawn while paused: blocks still apply (the opaque
     * head is carried without executing or recomputing the runtime) */
    fx.w->v2_runtime_table_n = 2;
    mk_env_block(&b, 5, gid, NULL);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
          "paused head carried without its runtime"); OK();

    /* RESUME fails closed without the exact runtime; succeeds with it —
     * and the head is CARRIED, never rebuilt. */
    static v2x_env_t eresume;
    CHECK(env_status(&eresume, fx.w, T3_DOMAIN, DNA_DOMST_ACTIVE, 1000)
              == 0, "eresume");     /* distinct bytes ⇒ distinct tx_id */
    mk_env_block(&b, 6, gid, &eresume);
    CHECK(expect_reject(fx.w, &b, "resume without runtime") == 0,
          "resume fails closed without the runtime"); OK();
    fx.w->v2_runtime_table_n = g_ext_n;
    mk_env_block(&b, 6, gid, &eresume);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0, "resume block");
    CHECK(head_blob(fx.w, T3_DOMAIN, blob2) == 0 &&
          memcmp(blob, blob2, DNA_V2_DOMHEAD_ENC_LEN) == 0,
          "resume carries the head unchanged"); OK();
    static v2x_env_t et3c;
    CHECK(env_tn_put(&et3c, T3_DOMAIN, 0x03, 5, T3_ASSET) == 0, "et3c");
    mk_env_block(&b, 7, gid, &et3c);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
          "executable after resume");
    CHECK(head_blob(fx.w, T3_DOMAIN, blob) == 0 && be64_at(blob + 68) == 2,
          "height 2 after resume execution"); OK();

    /* RETIRE: final head stays committed permanently; no execution; no
     * reactivation (terminal); roots reproducible after restart. */
    static v2x_env_t eretire;
    CHECK(env_status(&eretire, fx.w, T3_DOMAIN, DNA_DOMST_RETIRED, 0)
              == 0, "eretire");
    mk_env_block(&b, 8, gid, &eretire);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0, "retire block");
    CHECK(head_blob(fx.w, T3_DOMAIN, blob2) == 0 &&
          memcmp(blob, blob2, DNA_V2_DOMHEAD_ENC_LEN) == 0,
          "RETIRED head remains committed unchanged"); OK();
    static v2x_env_t et3d;
    CHECK(env_tn_put(&et3d, T3_DOMAIN, 0x04, 5, T3_ASSET) == 0, "et3d");
    mk_env_block(&b, 9, gid, &et3d);
    CHECK(expect_reject(fx.w, &b, "retired execution") == 0,
          "RETIRED admits no execution"); OK();
    {
        static v2x_env_t ereact;
        CHECK(env_status(&ereact, fx.w, T3_DOMAIN, DNA_DOMST_ACTIVE,
                         2000) == 0, "ereact");
        mk_env_block(&b, 9, gid, &ereact);
        CHECK(expect_reject(fx.w, &b, "retired reactivation") == 0,
              "RETIRED is terminal — reactivation rejects"); OK();
    }
    {
        uint8_t g2[64], g2b[64];
        CHECK(nodus_witness_global_root_v2(fx.w, g2, NULL, NULL, NULL)
                  == 0, "g2");
        CHECK(fx_reopen(&fx) == 0, "reopen post-retire");
        CHECK(nodus_witness_global_root_v2(fx.w, g2b, NULL, NULL, NULL)
                  == 0 && memcmp(g2, g2b, 64) == 0,
              "historical roots reproducible with the final head"); OK();
    }

    /* UNKNOWN lifecycle value: fail closed, never treated as any known
     * state (record status byte patched to 6 at offset 8). */
    {
        sqlite3_stmt *st = NULL;
        uint8_t rec[DNA_DOMREG_REC_ENC_LEN];
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "SELECT record FROM domain_registry WHERE domain_id=7",
              -1, &st, NULL) == SQLITE_OK &&
              sqlite3_step(st) == SQLITE_ROW &&
              sqlite3_column_bytes(st, 0) == DNA_DOMREG_REC_ENC_LEN,
              "record row");
        memcpy(rec, sqlite3_column_blob(st, 0), sizeof(rec));
        sqlite3_finalize(st);
        uint8_t bad[DNA_DOMREG_REC_ENC_LEN];
        memcpy(bad, rec, sizeof(bad));
        bad[8] = 6;                     /* unknown lifecycle value */
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "UPDATE domain_registry SET record=?1 WHERE domain_id=7",
              -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, bad, sizeof(bad), SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "patch");
        sqlite3_finalize(st);
        mk_env_block(&b, 9, gid, NULL);
        CHECK(expect_reject(fx.w, &b, "unknown lifecycle") == 0,
              "unknown lifecycle value fails closed"); OK();
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "UPDATE domain_registry SET record=?1 WHERE domain_id=7",
              -1, &st, NULL) == SQLITE_OK, "prep2");
        sqlite3_bind_blob(st, 1, rec, sizeof(rec), SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "restore");
        sqlite3_finalize(st);
    }

    /* ACTIVE with a MISSING head is consensus failure — never
     * synthesized. (Surgical deletion of CORE's committed head.) */
    {
        sqlite3_stmt *st = NULL;
        uint8_t core_head[DNA_V2_DOMHEAD_ENC_LEN];
        uint64_t ch = 0, cl = 0;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "SELECT head, domain_height, last_updated_global "
              "FROM v2_domain_heads WHERE domain_id=1", -1, &st, NULL)
                  == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW,
              "core head row");
        memcpy(core_head, sqlite3_column_blob(st, 0), sizeof(core_head));
        ch = (uint64_t)sqlite3_column_int64(st, 1);
        cl = (uint64_t)sqlite3_column_int64(st, 2);
        sqlite3_finalize(st);
        CHECK(run_sql(fx.w->db,
              "DELETE FROM v2_domain_heads WHERE domain_id=1") == 0,
              "delete");
        mk_env_block(&b, 9, gid, NULL);
        CHECK(expect_reject(fx.w, &b, "ACTIVE missing head") == 0,
              "ACTIVE domain with missing head rejects"); OK();
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "INSERT INTO v2_domain_heads (domain_id, head, "
              "domain_height, last_updated_global) VALUES (1,?1,?2,?3)",
              -1, &st, NULL) == SQLITE_OK, "prep3");
        sqlite3_bind_blob(st, 1, core_head, sizeof(core_head),
                          SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)ch);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)cl);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "restore head");
        sqlite3_finalize(st);
    }

    /* ACTIVE with an UNRESOLVED runtime rejects (drop CORE+T3 from the
     * table — SYSTEM alone remains). */
    {
        fx.w->v2_runtime_table_n = 1;   /* SYSTEM only */
        mk_env_block(&b, 9, gid, NULL);
        CHECK(expect_reject(fx.w, &b, "ACTIVE unresolved runtime") == 0,
              "ACTIVE domain with unresolved runtime rejects"); OK();
        fx.w->v2_runtime_table_n = g_ext_n;
    }

    fx_close(&fx);
    return 0;
}

int main(void) {
    CHECK(keys_init() == 0, "deterministic keys");
    CHECK(ext_table_init() == 0, "synthetic runtime table");
    if (test_migration()) return 1;
    if (test_absent_fixture()) return 1;
    if (test_dist_lifecycle()) return 1;
    if (test_order_independence()) return 1;
    if (test_never_mint()) return 1;
    if (test_genesis_rejects()) return 1;
    if (test_inactive_boundary()) return 1;
    if (test_generic_t3()) return 1;
    if (test_generic_unresolvable_target()) return 1;
    if (test_generic_coexistence()) return 1;
    if (test_lifecycle()) return 1;
    printf("test_v2_claims: ALL OK (%d checks)\n", g_checks);
    return 0;
}
