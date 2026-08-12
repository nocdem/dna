/**
 * Nodus — Ledger V2: the generic typed-effect + compiled STORAGE-ADAPTER
 * boundary (INACTIVE).
 *
 * Every effect result in this file is built through the REAL codec
 * (dna_effect_result_encode -> dna_effect_result_decode) and never by
 * hand, so the boundary under test is the shipped one: a view that the
 * codec would not produce is not a view this layer is allowed to see.
 *
 * The test domain is a SYNTHETIC runtime T5 (domain id 11 — T3=7 and
 * T4=9 are taken by test_v2_claims) whose adapter stores rows in a
 * TEST-ONLY table through PREPARED STATEMENTS ONLY: no key or value byte
 * is ever concatenated into SQL, which is what makes section 7's
 * injection payload provably opaque. A second synthetic runtime T6
 * (domain 13) shares the SAME compiled adapter code, so the only thing
 * separating their rows is the domain id the RESOLVED RUNTIME supplies.
 *
 * Sections:
 *   1. Adapter authority: exact five-axis resolution reaches the adapter;
 *      a missing adapter fails closed; an unknown op fails closed; each
 *      single wrong axis returns NULL, so partial-axis resolution cannot
 *      reach an adapter at all.
 *   2. End-to-end through the REAL generic path
 *      (nodus_witness_v2_runtime_for over a registry row).
 *   3. Domain authority: T5 and T6 write the same key without collision;
 *      the stored domain column always equals rt->domain_id.
 *   4. No SQL/table escape: an injection payload as BOTH key and value
 *      round-trips as opaque bytes and the table survives.
 *   5. Adapter self-check negative matrix.
 *   6. Per-op restrictions (kinds, precondition tags, blob bounds).
 *   7. Precondition truth against REAL storage (create/set/delete,
 *      expected version, expected value hash).
 *   8. The pure precondition decision matrix, including the
 *      unrepresentable version+hash combination.
 *   9. Fault vs verdict: a dropped table is a STORAGE FAULT, never a
 *      "missing row" and never an accept.
 *  10. Failure contract: first failure wins, fail_index is exact, and the
 *      CALLER's rollback restores the table byte-for-byte (digest).
 *  11. Purity + argument matrix + the valid EMPTY result.
 *
 * @file test_v2_effects.c
 */

/* mkdtemp() and lstat() are POSIX, not ISO C: under a strict -std=c11 the
 * glibc headers hide them and both calls become implicit declarations.
 * Declaring the feature set makes this file compile clean under
 * -std=c11 -Wall -Wextra -Werror -pedantic as well as in the project
 * build, where the default is already permissive (the
 * test_v2_env_preflight.c convention). */
#define _DEFAULT_SOURCE 1

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_v2_adapter.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_domreg.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/effect_wire.h"
#include "dnac/domain_wire.h"
#include "crypto/hash/qgp_sha3.h"

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

/* ── fs + fixture (the test_v2_claims discipline) ───────────────────── */

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

static int run_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL failed: %s\n", err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

/* The TEST-ONLY adapter table. `domain_id` is part of the primary key —
 * that is what lets two domains hold the same logical key without ever
 * colliding, and it is written from rt->domain_id alone. */
static const char *T5_TABLE_SQL =
    "CREATE TABLE t5_effect_state ("
    "domain_id INTEGER NOT NULL, "
    "k BLOB NOT NULL, "
    "v BLOB NOT NULL, "
    "version INTEGER NOT NULL, "
    "PRIMARY KEY (domain_id, k))";

static int fx_open(fixture_t *fx) {
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_effects_XXXXXX");
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain_id16, 0x5b, sizeof(fx->chain_id16));
    if (nodus_witness_create_chain_db(fx->w, fx->chain_id16) != 0) {
        rmrf(fx->dir); free(fx->w); fx->w = NULL;
        return -1;
    }
    nodus_chain_config_db_migrate(fx->w);
    if (run_sql(fx->w->db, T5_TABLE_SQL) != 0) {
        sqlite3_close(fx->w->db);
        rmrf(fx->dir); free(fx->w); fx->w = NULL;
        return -1;
    }
    return 0;
}

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) { sqlite3_close(fx->w->db); fx->w->db = NULL; }
    free(fx->w);
    fx->w = NULL;
    rmrf(fx->dir);
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

/* ── the compiled T5 adapter (probe + mutate, prepared statements) ──── */

#define T5_DOMAIN 11u
#define T6_DOMAIN 13u

static int g_probe_calls = 0;
static int g_mutate_calls = 0;

/**
 * Probe: read one row scoped by the AUTHORITATIVE domain the generic
 * layer supplied. A row reports (version, value-hash of the STORED
 * value); no row reports exists == 0; any sqlite error reports
 * ERR_STORAGE_FAULT and NEVER "absent".
 */
static nodus_adapter_status_t t5_probe(const nodus_domain_adapter_t *ad,
                                       struct nodus_witness *ww,
                                       uint32_t domain_id,
                                       const nodus_adapter_op_t *op,
                                       const uint8_t *key, uint16_t key_len,
                                       nodus_adapter_row_facts_t *facts) {
    (void)ad; (void)op;
    nodus_witness_t *w = (nodus_witness_t *)ww;
    if (!w || !w->db || !key || !facts) return NODUS_ADAPTER_ERR_ARG;
    g_probe_calls++;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT v, version FROM t5_effect_state "
            "WHERE domain_id=?1 AND k=?2", -1, &st, NULL) != SQLITE_OK)
        return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)domain_id);
    sqlite3_bind_blob(st, 2, key, (int)key_len, SQLITE_TRANSIENT);

    nodus_adapter_status_t out = NODUS_ADAPTER_ERR_STORAGE_FAULT;
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        const void *vb = sqlite3_column_blob(st, 0);
        int vl = sqlite3_column_bytes(st, 0);
        sqlite3_int64 ver = sqlite3_column_int64(st, 1);
        if (vl >= 0 && ver >= 0 &&
            dna_effect_value_hash((const uint8_t *)vb, (uint32_t)vl,
                                  facts->value_hash) == 0) {
            facts->exists = 1;
            facts->version = (uint64_t)ver;
            out = NODUS_ADAPTER_OK;
        }
    } else if (rc == SQLITE_DONE) {
        facts->exists = 0;
        out = NODUS_ADAPTER_OK;
    }
    sqlite3_finalize(st);
    return out;
}

/**
 * Mutate: the already-validated write, inside the CALLER's transaction.
 * Exactly one row must change; anything else is a storage fault.
 */
static nodus_adapter_status_t t5_mutate(const nodus_domain_adapter_t *ad,
                                        struct nodus_witness *ww,
                                        uint32_t domain_id,
                                        const nodus_adapter_op_t *op,
                                        uint8_t effect_kind,
                                        const uint8_t *key, uint16_t key_len,
                                        const uint8_t *value,
                                        uint32_t value_len) {
    (void)ad; (void)op;
    nodus_witness_t *w = (nodus_witness_t *)ww;
    if (!w || !w->db || !key) return NODUS_ADAPTER_ERR_ARG;
    if (!value && value_len > 0) return NODUS_ADAPTER_ERR_ARG;
    g_mutate_calls++;

    const char *sql = NULL;
    int binds_value = 0;
    switch (effect_kind) {
        case DNA_EFFECT_CREATE:
            sql = "INSERT INTO t5_effect_state (domain_id, k, v, version) "
                  "VALUES (?1, ?2, ?3, 1)";
            binds_value = 1;
            break;
        case DNA_EFFECT_SET:
            sql = "UPDATE t5_effect_state SET v=?3, version=version+1 "
                  "WHERE domain_id=?1 AND k=?2";
            binds_value = 1;
            break;
        case DNA_EFFECT_DELETE:
            sql = "DELETE FROM t5_effect_state "
                  "WHERE domain_id=?1 AND k=?2";
            break;
        default:
            return NODUS_ADAPTER_ERR_ARG;
    }

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)domain_id);
    sqlite3_bind_blob(st, 2, key, (int)key_len, SQLITE_TRANSIENT);
    if (binds_value)
        sqlite3_bind_blob(st, 3, value ? (const void *)value : (const void *)"",
                          (int)value_len, SQLITE_TRANSIENT);

    int rc = sqlite3_step(st);
    int changed = sqlite3_changes(w->db);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    if (changed != 1) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    return NODUS_ADAPTER_OK;
}

/**
 * Read: the mediated-read boundary (execution season) — the stored
 * VALUE, scoped by the authoritative domain, absent row = a successful
 * present==0 read, sqlite error = STORAGE FAULT and never "absent".
 */
static int g_read_calls = 0;

static nodus_adapter_status_t t5_read(const nodus_domain_adapter_t *ad,
                                      struct nodus_witness *ww,
                                      uint32_t domain_id,
                                      const nodus_adapter_op_t *op,
                                      const uint8_t *key, uint16_t key_len,
                                      int *present, uint8_t *value,
                                      uint32_t cap, uint32_t *vlen) {
    (void)ad; (void)op;
    nodus_witness_t *w = (nodus_witness_t *)ww;
    if (!w || !w->db || !key) return NODUS_ADAPTER_ERR_ARG;
    g_read_calls++;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT v FROM t5_effect_state WHERE domain_id=?1 AND k=?2",
            -1, &st, NULL) != SQLITE_OK)
        return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)domain_id);
    sqlite3_bind_blob(st, 2, key, (int)key_len, SQLITE_TRANSIENT);
    nodus_adapter_status_t out = NODUS_ADAPTER_ERR_STORAGE_FAULT;
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        const void *vb = sqlite3_column_blob(st, 0);
        int vl = sqlite3_column_bytes(st, 0);
        if (vl >= 0 && (uint32_t)vl <= cap) {
            if (vl > 0) memcpy(value, vb, (size_t)vl);
            *present = 1;
            *vlen = (uint32_t)vl;
            out = NODUS_ADAPTER_OK;
        }
    } else if (rc == SQLITE_DONE) {
        *present = 0;
        *vlen = 0;
        out = NODUS_ADAPTER_OK;
    }
    sqlite3_finalize(st);
    return out;
}

/* A ROGUE read: a status outside {OK, ERR_STORAGE_FAULT} — must be
 * COERCED. */
static nodus_adapter_status_t rogue_read(const nodus_domain_adapter_t *ad,
                                         struct nodus_witness *ww,
                                         uint32_t domain_id,
                                         const nodus_adapter_op_t *op,
                                         const uint8_t *key,
                                         uint16_t key_len, int *present,
                                         uint8_t *value, uint32_t cap,
                                         uint32_t *vlen) {
    (void)ad; (void)ww; (void)domain_id; (void)op; (void)key;
    (void)key_len; (void)present; (void)value; (void)cap; (void)vlen;
    return NODUS_ADAPTER_ERR_PRECOND_MISSING;    /* out of contract */
}

/* A LYING read: says OK but reports facts outside the contract. */
static nodus_adapter_status_t lying_read(const nodus_domain_adapter_t *ad,
                                         struct nodus_witness *ww,
                                         uint32_t domain_id,
                                         const nodus_adapter_op_t *op,
                                         const uint8_t *key,
                                         uint16_t key_len, int *present,
                                         uint8_t *value, uint32_t cap,
                                         uint32_t *vlen) {
    (void)ad; (void)ww; (void)domain_id; (void)op; (void)key;
    (void)key_len; (void)value; (void)cap;
    *present = 2;                                /* not 0/1            */
    *vlen = 0;
    return NODUS_ADAPTER_OK;
}

/**
 * A ROGUE probe: answers with a PRECONDITION status, which is outside the
 * probe contract {OK, ERR_STORAGE_FAULT}. The generic layer must COERCE
 * it to ERR_STORAGE_FAULT — a broken compiled adapter is a node fault,
 * and precondition statuses may only originate in the ONE shipped
 * decision table. */
static nodus_adapter_status_t rogue_probe(const nodus_domain_adapter_t *ad,
                                          struct nodus_witness *ww,
                                          uint32_t domain_id,
                                          const nodus_adapter_op_t *op,
                                          const uint8_t *key,
                                          uint16_t key_len,
                                          nodus_adapter_row_facts_t *facts) {
    (void)ad; (void)ww; (void)domain_id; (void)op; (void)key; (void)key_len;
    (void)facts;
    return NODUS_ADAPTER_ERR_PRECOND_MISSING;   /* out of contract */
}

/* op 1 = general KV; op 2 = a deliberately narrow op; op 7 is NOT
 * registered anywhere — it is the unknown-op probe. */
static const nodus_adapter_op_t T5_OPS[2] = {
    {
        .op_id = 1,
        .allowed_kinds = NODUS_ADAPTER_KINDS_ALL,
        .allowed_preconds = NODUS_ADAPTER_PRECONDS_ALL,
        .key_len_min = 1,   .key_len_max = 128,
        .value_len_min = 0, .value_len_max = 8192
    },
    {
        .op_id = 2,
        .allowed_kinds = NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_CREATE),
        .allowed_preconds =
            NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_ABSENT),
        .key_len_min = 8,   .key_len_max = 8,
        .value_len_min = 4, .value_len_max = 16
    }
};

static const nodus_domain_adapter_t T5_ADAPTER = {
    .adapter_version = NODUS_DOMAIN_ADAPTER_V1,
    .ops = T5_OPS,
    .n_ops = 2,
    .probe = t5_probe,
    .mutate = t5_mutate,
    .read = t5_read
};

/* ── synthetic runtimes T5 / T6 over the extended table ─────────────── */

/* A tagged root over one domain's own rows. Its VALUE is not asserted
 * anywhere; it exists because the generic registration path calls
 * state_root, and because it proves the two synthetic domains own
 * disjoint slices of the same physical table. */
static int tn_state_root(uint32_t domain_id, const char *tag16,
                         nodus_witness_t *w, uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT k, v, version FROM t5_effect_state "
            "WHERE domain_id=?1 ORDER BY k ASC", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)domain_id);

    static uint8_t buf[16384];
    memcpy(buf, tag16, 16);
    size_t n = 16;

    int rc, ret = -1;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const void *k = sqlite3_column_blob(st, 0);
        int kl = sqlite3_column_bytes(st, 0);
        const void *v = sqlite3_column_blob(st, 1);
        int vl = sqlite3_column_bytes(st, 1);
        sqlite3_int64 ver = sqlite3_column_int64(st, 2);
        if (kl < 0 || vl < 0 || ver < 0) goto done;
        if (n + (size_t)kl + (size_t)vl + 16 > sizeof(buf)) goto done;
        buf[n++] = (uint8_t)kl;
        if (kl > 0) { memcpy(buf + n, k, (size_t)kl); n += (size_t)kl; }
        buf[n++] = (uint8_t)vl;
        if (vl > 0) { memcpy(buf + n, v, (size_t)vl); n += (size_t)vl; }
        for (int i = 7; i >= 0; i--)
            buf[n++] = (uint8_t)(((uint64_t)ver >> (8 * i)) & 0xff);
    }
    if (rc != SQLITE_DONE) goto done;
    ret = qgp_sha3_512(buf, n, out) == 0 ? 0 : -1;
done:
    sqlite3_finalize(st);
    return ret;
}

static int t5_state_root(const nodus_domain_runtime_t *rt,
                         struct nodus_witness *w, uint8_t out[64]) {
    (void)rt;
    return tn_state_root(T5_DOMAIN, "T5.STATE.v1\0\0\0\0\0",
                         (nodus_witness_t *)w, out);
}
static int t6_state_root(const nodus_domain_runtime_t *rt,
                         struct nodus_witness *w, uint8_t out[64]) {
    (void)rt;
    return tn_state_root(T6_DOMAIN, "T6.STATE.v1\0\0\0\0\0",
                         (nodus_witness_t *)w, out);
}

/* SYSTEM + CORE (production, adapter-free) + T5 + T6 (both carrying the
 * SAME compiled adapter). Nothing in a header, a BlockID or the schema
 * changes to carry them — the adapter rides on the runtime descriptor. */
static nodus_domain_runtime_t g_ext_table[4];
static size_t g_ext_n = 0;
static const uint32_t TN_RULES[1] = { 1 };

static int ext_table_init(void) {
    size_t n = 0;
    const nodus_domain_runtime_t *b = nodus_runtime_builtin_table(&n);
    if (!b || n != 2) return -1;
    memcpy(&g_ext_table[0], &b[0], sizeof(b[0]));
    memcpy(&g_ext_table[1], &b[1], sizeof(b[1]));

    memset(&g_ext_table[2], 0, sizeof(g_ext_table[2]));
    g_ext_table[2].domain_id = T5_DOMAIN;
    g_ext_table[2].runtime_kind = DNA_RUNTIME_NATIVE_BUILTIN;
    g_ext_table[2].runtime_abi = NODUS_DOMAIN_RUNTIME_ABI_V1;
    g_ext_table[2].ruleset_version = 1;
    g_ext_table[2].descriptor.descriptor_version = DNA_RULESET_DESC_VERSION;
    g_ext_table[2].descriptor.domain_id = T5_DOMAIN;
    memcpy(g_ext_table[2].descriptor.name, "TEST_DOMAIN_5", 13);
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
    g_ext_table[2].state_root = t5_state_root;
    g_ext_table[2].invariant = NULL;
    g_ext_table[2].adapter = &T5_ADAPTER;

    memcpy(&g_ext_table[3], &g_ext_table[2], sizeof(g_ext_table[2]));
    g_ext_table[3].domain_id = T6_DOMAIN;
    g_ext_table[3].descriptor.domain_id = T6_DOMAIN;
    memset(g_ext_table[3].descriptor.name, 0, DNA_DOM_NAME_LEN);
    memcpy(g_ext_table[3].descriptor.name, "TEST_DOMAIN_6", 13);
    if (dna_ruleset_desc_hash(&g_ext_table[3].descriptor,
                              g_ext_table[3].ruleset_hash) != 0)
        return -1;
    g_ext_table[3].state_root = t6_state_root;
    /* SAME adapter pointer — the two domains differ ONLY in the id the
     * resolved runtime carries. */
    g_ext_table[3].adapter = &T5_ADAPTER;
    g_ext_n = 4;
    return 0;
}

static const nodus_domain_runtime_t *lookup_ext(const nodus_domain_runtime_t *e) {
    return nodus_runtime_lookup_in(g_ext_table, g_ext_n, e->domain_id,
                                   e->runtime_kind, e->runtime_abi,
                                   e->ruleset_version, e->ruleset_hash);
}

/* ── registry helpers (the test_v2_claims generic registration path) ── */

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

static int register_synthetic(nodus_witness_t *w,
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
    if (rt->state_root(rt, (struct nodus_witness *)w,
                       m.genesis_state_root) != 0)
        return -1;
    if (nodus_witness_domreg_op_register(w, &m) != 0) return -1;
    return set_domain_status(w, rt->domain_id, DNA_DOMST_ACTIVE);
}

/* ── result construction (through the REAL codec, always) ───────────── */

typedef struct {
    uint8_t           bytes[16384];
    dna_effect_view_t view;
} result_t;

static void eff_set(dna_effect_in_t *e, uint32_t op_id, uint8_t kind,
                    uint8_t tag, const uint8_t *key, uint16_t key_len,
                    const uint8_t *value, uint32_t value_len) {
    memset(e, 0, sizeof(*e));
    e->hdr.op_id = op_id;
    e->hdr.effect_kind = kind;
    e->hdr.precond_tag = tag;
    e->hdr.key_len = key_len;
    e->hdr.value_len = value_len;
    e->key = key;
    e->value = value;
}

static int mk_result(const dna_effect_in_t *ins, uint16_t n, result_t *r) {
    size_t written = 0;
    memset(r, 0, sizeof(*r));
    if (dna_effect_result_encode(ins, n, r->bytes, sizeof(r->bytes),
                                 &written) != 0)
        return -1;
    return dna_effect_result_decode(r->bytes, written, &r->view);
}

/* One CREATE/ABSENT effect on op 1 — the workhorse of the storage
 * sections. */
static int mk_one(result_t *r, uint32_t op_id, uint8_t kind, uint8_t tag,
                  const char *key, const char *value,
                  uint64_t expect_ver, const uint8_t *expect_vhash) {
    dna_effect_in_t e;
    eff_set(&e, op_id, kind, tag, (const uint8_t *)key,
            (uint16_t)strlen(key),
            value ? (const uint8_t *)value : NULL,
            value ? (uint32_t)strlen(value) : 0u);
    e.hdr.expected_version = expect_ver;
    if (expect_vhash) memcpy(e.hdr.expected_vhash, expect_vhash, 64);
    return mk_result(&e, 1, r);
}

/* ── storage inspection ─────────────────────────────────────────────── */

/** @return 1 found (outs filled), 0 absent, -1 fault. */
static int row_get(nodus_witness_t *w, uint32_t domain_id, const char *key,
                   uint8_t *val_out, int *val_len_out, uint64_t *ver_out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT v, version FROM t5_effect_state "
            "WHERE domain_id=?1 AND k=?2", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)domain_id);
    sqlite3_bind_blob(st, 2, key, (int)strlen(key), SQLITE_TRANSIENT);
    int rc = sqlite3_step(st), ret = -1;
    if (rc == SQLITE_ROW) {
        const void *v = sqlite3_column_blob(st, 0);
        int vl = sqlite3_column_bytes(st, 0);
        if (val_out && vl > 0) memcpy(val_out, v, (size_t)vl);
        if (val_len_out) *val_len_out = vl;
        if (ver_out) *ver_out = (uint64_t)sqlite3_column_int64(st, 1);
        ret = 1;
    } else if (rc == SQLITE_DONE) {
        ret = 0;
    }
    sqlite3_finalize(st);
    return ret;
}

/** Ordered full-table digest — the rollback oracle (never a return code). */
static int t5_digest(nodus_witness_t *w, uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT domain_id, k, v, version FROM t5_effect_state "
            "ORDER BY domain_id ASC, k ASC", -1, &st, NULL) != SQLITE_OK)
        return -1;
    static uint8_t buf[16384];
    size_t n = 0;
    int rc, ret = -1;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        sqlite3_int64 dom = sqlite3_column_int64(st, 0);
        const void *k = sqlite3_column_blob(st, 1);
        int kl = sqlite3_column_bytes(st, 1);
        const void *v = sqlite3_column_blob(st, 2);
        int vl = sqlite3_column_bytes(st, 2);
        sqlite3_int64 ver = sqlite3_column_int64(st, 3);
        if (kl < 0 || vl < 0) goto done;
        if (n + (size_t)kl + (size_t)vl + 32 > sizeof(buf)) goto done;
        for (int i = 7; i >= 0; i--)
            buf[n++] = (uint8_t)(((uint64_t)dom >> (8 * i)) & 0xff);
        buf[n++] = (uint8_t)kl;
        if (kl > 0) { memcpy(buf + n, k, (size_t)kl); n += (size_t)kl; }
        buf[n++] = (uint8_t)vl;
        if (vl > 0) { memcpy(buf + n, v, (size_t)vl); n += (size_t)vl; }
        for (int i = 7; i >= 0; i--)
            buf[n++] = (uint8_t)(((uint64_t)ver >> (8 * i)) & 0xff);
    }
    if (rc != SQLITE_DONE) goto done;
    ret = qgp_sha3_512(buf, n, out) == 0 ? 0 : -1;
done:
    sqlite3_finalize(st);
    return ret;
}

/* ══ 1. adapter authority ═══════════════════════════════════════════ */

static int test_adapter_authority(void) {
    fixture_t fx;
    CHECK(fx_open(&fx) == 0, "fixture");
    fx.w->v2_runtime_table = g_ext_table;
    fx.w->v2_runtime_table_n = g_ext_n;

    /* the EXACT registered adapter is reachable through the exact tuple */
    const nodus_domain_runtime_t *rt = lookup_ext(&g_ext_table[2]);
    CHECK(rt != NULL, "T5 resolves");
    CHECK(rt->adapter == &T5_ADAPTER, "T5 carries the registered adapter");
    CHECK(nodus_adapter_selfcheck(rt->adapter) == 0, "adapter selfcheck");
    OK();

    /* a small valid result applies, and the rows land under T5's OWN
     * domain id — which came from rt->domain_id and nowhere else */
    const uint8_t k1[2] = { 'k', '1' }, k2[2] = { 'k', '2' };
    const uint8_t v1[2] = { 'V', '1' }, v2[2] = { 'V', '2' };
    dna_effect_in_t ins[2];
    eff_set(&ins[0], 1, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
            k1, 2, v1, 2);
    eff_set(&ins[1], 1, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
            k2, 2, v2, 2);
    result_t r;
    CHECK(mk_result(ins, 2, &r) == 0, "encode+decode 2 effects");
    CHECK(r.view.effect_count == 2 && r.view.buf != NULL, "decoded view");

    uint16_t fi = 0xFFFF;
    CHECK(nodus_witness_v2_effects_validate(rt, &r.view, &fi) ==
          NODUS_ADAPTER_OK, "validate OK");
    CHECK(fi == 0, "fail_index 0 on success");
    fi = 0xFFFF;
    CHECK(nodus_witness_v2_effects_apply((struct nodus_witness *)fx.w, rt,
                                         &r.view, &fi) == NODUS_ADAPTER_OK,
          "apply OK");
    CHECK(fi == 0, "fail_index 0 on success");
    OK();

    CHECK(q1(fx.w, "SELECT COUNT(*) FROM t5_effect_state") == 2,
          "two rows landed");
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM t5_effect_state "
                   "WHERE domain_id=11") == 2,
          "rows carry the RESOLVED runtime's domain id");
    uint64_t ver = 0;
    int vl = 0;
    uint8_t vb[64];
    CHECK(row_get(fx.w, T5_DOMAIN, "k1", vb, &vl, &ver) == 1 &&
          vl == 2 && memcmp(vb, "V1", 2) == 0 && ver == 1,
          "k1 stored verbatim at version 1");
    OK();

    /* a runtime with NO adapter fails closed — and the PRODUCTION table
     * is exactly such a table (selfcheck enforces it) */
    size_t bn = 0;
    const nodus_domain_runtime_t *builtin = nodus_runtime_builtin_table(&bn);
    CHECK(builtin != NULL && bn == 2, "builtin table");
    CHECK(builtin[0].adapter == NULL && builtin[1].adapter == NULL,
          "no production runtime carries an adapter");
    CHECK(nodus_witness_runtime_selfcheck() == 0,
          "production selfcheck still green with the new field");
    fi = 0xFFFF;
    CHECK(nodus_witness_v2_effects_validate(&builtin[1], &r.view, &fi) ==
          NODUS_ADAPTER_ERR_NO_ADAPTER, "CORE has no adapter");
    CHECK(fi == 0, "result-level reject reports index 0");
    CHECK(nodus_witness_v2_effects_apply((struct nodus_witness *)fx.w,
                                         &builtin[1], &r.view, NULL) ==
          NODUS_ADAPTER_ERR_NO_ADAPTER, "apply refuses an adapterless rt");
    OK();

    /* an unknown op never resolves to a "closest" one */
    result_t ru;
    CHECK(mk_one(&ru, 7, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
                 "zz", "x", 0, NULL) == 0, "encode unknown-op effect");
    fi = 0xFFFF;
    CHECK(nodus_witness_v2_effects_validate(rt, &ru.view, &fi) ==
          NODUS_ADAPTER_ERR_UNKNOWN_OP, "op 7 unknown");
    CHECK(fi == 0, "fail index = the failing effect");
    CHECK(nodus_adapter_op_lookup(&T5_ADAPTER, 7) == NULL, "no op 7");
    CHECK(nodus_adapter_op_lookup(&T5_ADAPTER, 0) == NULL, "no op 0");
    CHECK(nodus_adapter_op_lookup(&T5_ADAPTER, 3) == NULL, "no op 3");
    CHECK(nodus_adapter_op_lookup(NULL, 1) == NULL, "NULL adapter lookup");
    CHECK(nodus_adapter_op_lookup(&T5_ADAPTER, 1) == &T5_OPS[0] &&
          nodus_adapter_op_lookup(&T5_ADAPTER, 2) == &T5_OPS[1],
          "registered ops resolve exactly");
    OK();

    /* the unknown op is a per-effect reject: index 1 of a 2-effect result */
    dna_effect_in_t mix[2];
    const uint8_t mk1[2] = { 'm', '1' };
    const uint8_t mk2[2] = { 'm', '2' };
    eff_set(&mix[0], 1, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
            mk1, 2, v1, 2);
    eff_set(&mix[1], 7, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
            mk2, 2, v2, 2);
    result_t rm;
    CHECK(mk_result(mix, 2, &rm) == 0, "encode mixed result");
    fi = 0xFFFF;
    CHECK(nodus_witness_v2_effects_validate(rt, &rm.view, &fi) ==
          NODUS_ADAPTER_ERR_UNKNOWN_OP, "unknown op at index 1");
    CHECK(fi == 1, "fail_index == 1");
    OK();

    /* FIVE-AXIS DISCIPLINE: each single wrong axis returns NULL, so no
     * partial-axis resolution can ever reach an adapter */
    const nodus_domain_runtime_t *e = &g_ext_table[2];
    CHECK(nodus_runtime_lookup_in(g_ext_table, g_ext_n, e->domain_id + 1,
                                  e->runtime_kind, e->runtime_abi,
                                  e->ruleset_version, e->ruleset_hash)
          == NULL, "wrong domain_id");
    CHECK(nodus_runtime_lookup_in(g_ext_table, g_ext_n, e->domain_id,
                                  (uint8_t)(e->runtime_kind + 1),
                                  e->runtime_abi, e->ruleset_version,
                                  e->ruleset_hash) == NULL,
          "wrong runtime_kind");
    CHECK(nodus_runtime_lookup_in(g_ext_table, g_ext_n, e->domain_id,
                                  e->runtime_kind, e->runtime_abi + 1,
                                  e->ruleset_version, e->ruleset_hash)
          == NULL, "wrong runtime_abi");
    CHECK(nodus_runtime_lookup_in(g_ext_table, g_ext_n, e->domain_id,
                                  e->runtime_kind, e->runtime_abi,
                                  e->ruleset_version + 1, e->ruleset_hash)
          == NULL, "wrong ruleset_version");
    uint8_t flipped[DNA_DOM_HASH_LEN];
    memcpy(flipped, e->ruleset_hash, sizeof(flipped));
    flipped[37] ^= 0x01;
    CHECK(nodus_runtime_lookup_in(g_ext_table, g_ext_n, e->domain_id,
                                  e->runtime_kind, e->runtime_abi,
                                  e->ruleset_version, flipped) == NULL,
          "one flipped ruleset_hash byte");
    OK();

    fx_close(&fx);
    return 0;
}

/* ══ 2. end-to-end through the REAL generic resolution path ═════════ */

static int test_end_to_end_registry(void) {
    fixture_t fx;
    CHECK(fx_open(&fx) == 0, "fixture");
    fx.w->v2_runtime_table = g_ext_table;
    fx.w->v2_runtime_table_n = g_ext_n;

    CHECK(register_synthetic(fx.w, &g_ext_table[2]) == 0, "register T5");

    const nodus_domain_runtime_t *rt = NULL;
    CHECK(nodus_witness_v2_runtime_for(fx.w, T5_DOMAIN, 1, &rt) == 0,
          "runtime_for resolves T5 through the registry");
    CHECK(rt != NULL && rt->adapter == &T5_ADAPTER,
          "the generic path reaches the registered adapter");
    OK();

    result_t r;
    CHECK(mk_one(&r, 1, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
                 "e2e", "payload", 0, NULL) == 0, "encode");
    CHECK(nodus_witness_v2_effects_apply((struct nodus_witness *)fx.w, rt,
                                         &r.view, NULL) == NODUS_ADAPTER_OK,
          "apply through the resolved runtime");
    uint64_t ver = 0;
    int vl = 0;
    uint8_t vb[64];
    CHECK(row_get(fx.w, T5_DOMAIN, "e2e", vb, &vl, &ver) == 1 &&
          vl == 7 && memcmp(vb, "payload", 7) == 0 && ver == 1,
          "row landed under T5");
    OK();

    /* an INACTIVE domain cannot be resolved at all, so its adapter is
     * unreachable — fail-closed, upstream of this whole layer */
    CHECK(set_domain_status(fx.w, T5_DOMAIN, DNA_DOMST_REGISTERED) == 0,
          "flip T5 back to REGISTERED");
    const nodus_domain_runtime_t *rt2 = (const nodus_domain_runtime_t *)1;
    CHECK(nodus_witness_v2_runtime_for(fx.w, T5_DOMAIN, 1, &rt2) != 0 &&
          rt2 == NULL, "inactive domain does not resolve");
    OK();

    fx_close(&fx);
    return 0;
}

/* ══ 3. domain authority: two domains, one adapter, one key ════════ */

static int test_domain_authority(void) {
    fixture_t fx;
    CHECK(fx_open(&fx) == 0, "fixture");
    fx.w->v2_runtime_table = g_ext_table;
    fx.w->v2_runtime_table_n = g_ext_n;

    /* NOTE (structural, not empirical): no public field of this boundary
     * carries a domain id at all. The codec states it outright —
     * effect_wire.h:9-14 "NO domain id — the authoritative domain is
     * engine-supplied CONTEXT" — and neither validate nor apply takes a
     * domain parameter. The plumbing below is the empirical half: the
     * stored domain column always equals the RESOLVED runtime's id. */
    const nodus_domain_runtime_t *rt5 = lookup_ext(&g_ext_table[2]);
    const nodus_domain_runtime_t *rt6 = lookup_ext(&g_ext_table[3]);
    CHECK(rt5 && rt6, "both synthetic runtimes resolve");
    CHECK(rt5->adapter == rt6->adapter,
          "the two runtimes share ONE compiled adapter");
    CHECK(rt5->domain_id == T5_DOMAIN && rt6->domain_id == T6_DOMAIN,
          "and differ only in the domain the runtime carries");
    OK();

    result_t r5, r6;
    CHECK(mk_one(&r5, 1, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
                 "shared", "five", 0, NULL) == 0, "encode T5 effect");
    CHECK(mk_one(&r6, 1, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
                 "shared", "six", 0, NULL) == 0, "encode T6 effect");

    CHECK(nodus_witness_v2_effects_apply((struct nodus_witness *)fx.w, rt5,
                                         &r5.view, NULL) == NODUS_ADAPTER_OK,
          "T5 create");
    /* The SAME logical key through T6: this can only succeed because the
     * probe was scoped by rt->domain_id — a caller-supplied or defaulted
     * domain would have reported the T5 row and failed ABSENT. */
    CHECK(nodus_witness_v2_effects_apply((struct nodus_witness *)fx.w, rt6,
                                         &r6.view, NULL) == NODUS_ADAPTER_OK,
          "T6 create on the same key");
    OK();

    uint8_t vb[64];
    int vl = 0;
    uint64_t ver = 0;
    CHECK(row_get(fx.w, T5_DOMAIN, "shared", vb, &vl, &ver) == 1 &&
          vl == 4 && memcmp(vb, "five", 4) == 0, "T5 row intact");
    CHECK(row_get(fx.w, T6_DOMAIN, "shared", vb, &vl, &ver) == 1 &&
          vl == 3 && memcmp(vb, "six", 3) == 0, "T6 row intact");
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM t5_effect_state") == 2,
          "two coexisting rows");
    CHECK(q1(fx.w, "SELECT COUNT(DISTINCT domain_id) FROM t5_effect_state")
          == 2, "under two DIFFERENT domain ids");
    OK();

    /* a DELETE through T6 cannot reach T5's row */
    result_t rd;
    CHECK(mk_one(&rd, 1, DNA_EFFECT_DELETE, DNA_EFFECT_PRE_EXISTS,
                 "shared", NULL, 0, NULL) == 0, "encode delete");
    CHECK(nodus_witness_v2_effects_apply((struct nodus_witness *)fx.w, rt6,
                                         &rd.view, NULL) == NODUS_ADAPTER_OK,
          "T6 delete");
    CHECK(row_get(fx.w, T6_DOMAIN, "shared", NULL, NULL, NULL) == 0,
          "T6 row gone");
    CHECK(row_get(fx.w, T5_DOMAIN, "shared", NULL, NULL, NULL) == 1,
          "T5 row untouched by another domain's delete");
    OK();

    fx_close(&fx);
    return 0;
}

/* ══ 4. no SQL / table escape ═══════════════════════════════════════ */

static int test_injection_is_opaque(void) {
    fixture_t fx;
    CHECK(fx_open(&fx) == 0, "fixture");
    fx.w->v2_runtime_table = g_ext_table;
    fx.w->v2_runtime_table_n = g_ext_n;
    const nodus_domain_runtime_t *rt = lookup_ext(&g_ext_table[2]);
    CHECK(rt != NULL, "T5 resolves");

    static const char PAYLOAD[] = "'; DROP TABLE t5_effect_state; --";
    const size_t plen = strlen(PAYLOAD);

    result_t r;
    CHECK(mk_one(&r, 1, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
                 PAYLOAD, PAYLOAD, 0, NULL) == 0, "encode payload effect");
    CHECK(r.view.eff[0].key_len == (uint16_t)plen &&
          r.view.eff[0].value_len == (uint32_t)plen,
          "payload carried as opaque bytes of the right length");
    CHECK(nodus_witness_v2_effects_apply((struct nodus_witness *)fx.w, rt,
                                         &r.view, NULL) == NODUS_ADAPTER_OK,
          "payload applies like any other blob");
    OK();

    uint8_t vb[128];
    int vl = 0;
    uint64_t ver = 0;
    CHECK(row_get(fx.w, T5_DOMAIN, PAYLOAD, vb, &vl, &ver) == 1 &&
          vl == (int)plen && memcmp(vb, PAYLOAD, plen) == 0 && ver == 1,
          "the exact payload bytes are the key AND the value");
    OK();

    /* the table is still there and still serves probes — prepared
     * statements make injection through effect bytes impossible */
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM t5_effect_state") == 1,
          "table survived");
    result_t r2;
    CHECK(mk_one(&r2, 1, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
                 "after", "ok", 0, NULL) == 0, "encode follow-up");
    CHECK(nodus_witness_v2_effects_apply((struct nodus_witness *)fx.w, rt,
                                         &r2.view, NULL) == NODUS_ADAPTER_OK,
          "probes and writes still work after the payload");
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM t5_effect_state") == 2,
          "two rows");
    OK();

    fx_close(&fx);
    return 0;
}

/* ══ 5. adapter self-check negatives ════════════════════════════════ */

static int test_selfcheck_matrix(void) {
    CHECK(nodus_adapter_selfcheck(&T5_ADAPTER) == 0, "real adapter healthy");
    CHECK(nodus_adapter_selfcheck(NULL) == -1, "NULL adapter");
    OK();

    nodus_domain_adapter_t a;
    nodus_adapter_op_t ops[2];

    /* helper shape: a fresh healthy copy for every mutation */
#define FRESH() do { \
        a = T5_ADAPTER; \
        memcpy(ops, T5_OPS, sizeof(ops)); \
        a.ops = ops; a.n_ops = 2; \
    } while (0)

    FRESH(); CHECK(nodus_adapter_selfcheck(&a) == 0, "fresh copy healthy");

    FRESH(); a.adapter_version = 2;
    CHECK(nodus_adapter_selfcheck(&a) == -1, "wrong adapter_version");
    FRESH(); a.adapter_version = 0;
    CHECK(nodus_adapter_selfcheck(&a) == -1, "zero adapter_version");
    FRESH(); a.ops = NULL;
    CHECK(nodus_adapter_selfcheck(&a) == -1, "NULL ops");
    FRESH(); a.n_ops = 0;
    CHECK(nodus_adapter_selfcheck(&a) == -1, "zero n_ops");
    FRESH(); a.probe = NULL;
    CHECK(nodus_adapter_selfcheck(&a) == -1, "NULL probe");
    FRESH(); a.mutate = NULL;
    CHECK(nodus_adapter_selfcheck(&a) == -1, "NULL mutate");
    OK();

    FRESH(); ops[0].op_id = 9;   /* {9, 2} — descending */
    CHECK(nodus_adapter_selfcheck(&a) == -1, "descending op ids");
    FRESH(); ops[1].op_id = 1;   /* {1, 1} — duplicate */
    CHECK(nodus_adapter_selfcheck(&a) == -1, "duplicate op ids");
    OK();

    FRESH(); ops[0].key_len_min = 9; ops[0].key_len_max = 8;
    CHECK(nodus_adapter_selfcheck(&a) == -1, "key min > max");
    FRESH(); ops[0].value_len_min = 100; ops[0].value_len_max = 50;
    CHECK(nodus_adapter_selfcheck(&a) == -1, "value min > max");
    FRESH(); ops[0].key_len_max = DNA_EFFECT_MAX_KEY_LEN + 1;
    CHECK(nodus_adapter_selfcheck(&a) == -1, "key max beyond codec cap");
    FRESH(); ops[0].value_len_max = DNA_EFFECT_MAX_VALUE_LEN + 1;
    CHECK(nodus_adapter_selfcheck(&a) == -1, "value max beyond codec cap");
    FRESH(); ops[0].key_len_max = DNA_EFFECT_MAX_KEY_LEN;
    ops[0].value_len_max = DNA_EFFECT_MAX_VALUE_LEN;
    CHECK(nodus_adapter_selfcheck(&a) == 0, "exactly at the caps is legal");
    OK();

    FRESH(); ops[0].allowed_kinds = 0;
    CHECK(nodus_adapter_selfcheck(&a) == -1, "zero kind mask");
    FRESH(); ops[0].allowed_kinds = 0x08;
    CHECK(nodus_adapter_selfcheck(&a) == -1, "undefined kind bit");
    FRESH(); ops[0].allowed_kinds = (uint8_t)(NODUS_ADAPTER_KINDS_ALL | 0x80);
    CHECK(nodus_adapter_selfcheck(&a) == -1, "high kind bit set");
    FRESH(); ops[0].allowed_preconds = 0;
    CHECK(nodus_adapter_selfcheck(&a) == -1, "zero precond mask");
    FRESH(); ops[0].allowed_preconds = 0x10;
    CHECK(nodus_adapter_selfcheck(&a) == -1, "undefined precond bit");
    OK();

    /* the second op is judged too, not just the first */
    FRESH(); ops[1].allowed_kinds = 0;
    CHECK(nodus_adapter_selfcheck(&a) == -1, "every op is judged");
    OK();

    /* DEAD-OP shapes: the masks must be SATISFIABLE under the codec's
     * CREATE <=> ABSENT biconditional, and an op allowing DELETE needs a
     * zero value floor (the codec pins a DELETE's value_len to 0). Each
     * fails in the DENY direction — the point is that a compiled adapter
     * cannot SHIP believing it registered a path that can never fire. */
    FRESH();
    ops[0].allowed_kinds = NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_CREATE);
    ops[0].allowed_preconds = NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_EXISTS);
    CHECK(nodus_adapter_selfcheck(&a) == -1, "CREATE without ABSENT is dead");
    FRESH();
    ops[0].allowed_kinds = (uint8_t)(NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_SET) |
                                     NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_DELETE));
    ops[0].allowed_preconds = NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_ABSENT);
    CHECK(nodus_adapter_selfcheck(&a) == -1,
          "SET/DELETE without any EXISTS* is dead");
    FRESH();
    ops[0].allowed_kinds = NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_SET);
    ops[0].allowed_preconds = NODUS_ADAPTER_PRECONDS_ALL;
    CHECK(nodus_adapter_selfcheck(&a) == -1, "ABSENT without CREATE is dead");
    FRESH();
    ops[0].allowed_kinds = NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_CREATE);
    ops[0].allowed_preconds =
        (uint8_t)(NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_ABSENT) |
                  NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_EXISTS));
    CHECK(nodus_adapter_selfcheck(&a) == -1, "EXISTS without SET/DELETE is dead");
    FRESH();
    ops[0].value_len_min = 1;           /* op 1 allows DELETE */
    CHECK(nodus_adapter_selfcheck(&a) == -1,
          "DELETE with a nonzero value floor is dead");
    /* ...and a NARROW-but-satisfiable op is healthy */
    FRESH();
    ops[0].allowed_kinds = NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_SET);
    ops[0].allowed_preconds = NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_EXISTS);
    CHECK(nodus_adapter_selfcheck(&a) == 0, "SET+EXISTS-only op is legal");
    OK();

    /* a malformed adapter reaches validate as ERR_ARG, never as an
     * accept and never as "no adapter" */
    nodus_domain_runtime_t bad_rt = g_ext_table[2];
    FRESH(); a.probe = NULL;
    bad_rt.adapter = &a;
    result_t r;
    CHECK(mk_one(&r, 1, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
                 "x", "y", 0, NULL) == 0, "encode");
    CHECK(nodus_witness_v2_effects_validate(&bad_rt, &r.view, NULL) ==
          NODUS_ADAPTER_ERR_ARG, "malformed adapter -> ERR_ARG");
    OK();
#undef FRESH
    return 0;
}

/* ══ 6. per-op restrictions ═════════════════════════════════════════ */

static int test_op_restrictions(void) {
    fixture_t fx;
    CHECK(fx_open(&fx) == 0, "fixture");
    fx.w->v2_runtime_table = g_ext_table;
    fx.w->v2_runtime_table_n = g_ext_n;
    const nodus_domain_runtime_t *rt = lookup_ext(&g_ext_table[2]);
    CHECK(rt != NULL, "T5 resolves");

    /* op 2 accepts its exact shape */
    result_t r;
    CHECK(mk_one(&r, 2, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
                 "eightkey", "abcd", 0, NULL) == 0, "encode op2 create");
    CHECK(nodus_witness_v2_effects_validate(rt, &r.view, NULL) ==
          NODUS_ADAPTER_OK, "op2 exact shape validates");
    CHECK(nodus_witness_v2_effects_apply((struct nodus_witness *)fx.w, rt,
                                         &r.view, NULL) == NODUS_ADAPTER_OK,
          "op2 exact shape applies");
    CHECK(row_get(fx.w, T5_DOMAIN, "eightkey", NULL, NULL, NULL) == 1,
          "op2 row landed");
    OK();

    /* a kind op 2 does not permit */
    uint16_t fi = 0xFFFF;
    CHECK(mk_one(&r, 2, DNA_EFFECT_SET, DNA_EFFECT_PRE_EXISTS,
                 "eightkey", "abcd", 0, NULL) == 0, "encode op2 SET");
    CHECK(nodus_witness_v2_effects_validate(rt, &r.view, &fi) ==
          NODUS_ADAPTER_ERR_KIND, "SET via op2 -> ERR_KIND");
    CHECK(fi == 0, "fail index");
    CHECK(mk_one(&r, 2, DNA_EFFECT_DELETE, DNA_EFFECT_PRE_EXISTS,
                 "eightkey", NULL, 0, NULL) == 0, "encode op2 DELETE");
    CHECK(nodus_witness_v2_effects_validate(rt, &r.view, NULL) ==
          NODUS_ADAPTER_ERR_KIND, "DELETE via op2 -> ERR_KIND");
    OK();

    /* a precondition tag the op does not permit.
     *
     * HONEST LABEL: this leg CANNOT be exercised through op 2 as
     * specified. op 2 permits only CREATE, and the codec's biconditional
     * (effect_wire.h:86-99) forces CREATE to carry ABSENT — which op 2
     * permits — so the combination "kind allowed, tag not allowed" is
     * UNREPRESENTABLE for op 2. Building the result by hand to reach it
     * would test a view the shipped codec can never produce. The gate is
     * therefore exercised on an op that permits a kind with a NARROWER
     * tag set, which is the same code path with a constructible witness. */
    static const nodus_adapter_op_t NARROW_OPS[1] = {
        {
            .op_id = 1,
            .allowed_kinds = NODUS_ADAPTER_KINDS_ALL,
            .allowed_preconds =
                (uint8_t)(NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_ABSENT) |
                          NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_EXISTS)),
            .key_len_min = 1,   .key_len_max = 128,
            .value_len_min = 0, .value_len_max = 8192
        }
    };
    nodus_domain_adapter_t narrow = T5_ADAPTER;
    narrow.ops = NARROW_OPS;
    narrow.n_ops = 1;
    CHECK(nodus_adapter_selfcheck(&narrow) == 0, "narrow adapter healthy");
    nodus_domain_runtime_t narrow_rt = g_ext_table[2];
    narrow_rt.adapter = &narrow;

    CHECK(mk_one(&r, 1, DNA_EFFECT_SET, DNA_EFFECT_PRE_EXISTS_VERSION,
                 "eightkey", "abcd", 4, NULL) == 0, "encode version precond");
    CHECK(nodus_witness_v2_effects_validate(&narrow_rt, &r.view, NULL) ==
          NODUS_ADAPTER_ERR_PRECOND_FORM,
          "a tag the op does not permit -> ERR_PRECOND_FORM");
    uint8_t vh[64];
    CHECK(dna_effect_value_hash((const uint8_t *)"abcd", 4, vh) == 0,
          "value hash");
    CHECK(mk_one(&r, 1, DNA_EFFECT_SET, DNA_EFFECT_PRE_EXISTS_VHASH,
                 "eightkey", "abcd", 0, vh) == 0, "encode vhash precond");
    CHECK(nodus_witness_v2_effects_validate(&narrow_rt, &r.view, NULL) ==
          NODUS_ADAPTER_ERR_PRECOND_FORM,
          "vhash tag the op does not permit -> ERR_PRECOND_FORM");
    /* and the tags it DOES permit still pass the gate */
    CHECK(mk_one(&r, 1, DNA_EFFECT_SET, DNA_EFFECT_PRE_EXISTS,
                 "eightkey", "abcd", 0, NULL) == 0, "encode exists precond");
    CHECK(nodus_witness_v2_effects_validate(&narrow_rt, &r.view, NULL) ==
          NODUS_ADAPTER_OK, "a permitted tag passes");
    OK();

    /* op 2's blob bounds, both ends, both blobs */
    CHECK(mk_one(&r, 2, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
                 "sevenky", "abcd", 0, NULL) == 0, "encode 7-byte key");
    CHECK(nodus_witness_v2_effects_validate(rt, &r.view, NULL) ==
          NODUS_ADAPTER_ERR_SHAPE, "key len 7 -> ERR_SHAPE");
    CHECK(mk_one(&r, 2, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
                 "ninekeyy", "abcd", 0, NULL) == 0, "encode 8-byte key");
    CHECK(nodus_witness_v2_effects_validate(rt, &r.view, NULL) ==
          NODUS_ADAPTER_OK, "key len 8 accepted");
    CHECK(mk_one(&r, 2, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
                 "ninekeyyy", "abcd", 0, NULL) == 0, "encode 9-byte key");
    CHECK(nodus_witness_v2_effects_validate(rt, &r.view, NULL) ==
          NODUS_ADAPTER_ERR_SHAPE, "key len 9 -> ERR_SHAPE");
    OK();

    CHECK(mk_one(&r, 2, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
                 "eightke2", "abc", 0, NULL) == 0, "encode 3-byte value");
    CHECK(nodus_witness_v2_effects_validate(rt, &r.view, NULL) ==
          NODUS_ADAPTER_ERR_SHAPE, "value len 3 -> ERR_SHAPE");
    CHECK(mk_one(&r, 2, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
                 "eightke2", "0123456789abcdef", 0, NULL) == 0,
          "encode 16-byte value");
    CHECK(nodus_witness_v2_effects_validate(rt, &r.view, NULL) ==
          NODUS_ADAPTER_OK, "value len 16 accepted");
    CHECK(mk_one(&r, 2, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
                 "eightke2", "0123456789abcdefg", 0, NULL) == 0,
          "encode 17-byte value");
    CHECK(nodus_witness_v2_effects_validate(rt, &r.view, NULL) ==
          NODUS_ADAPTER_ERR_SHAPE, "value len 17 -> ERR_SHAPE");
    OK();

    /* nothing above the first accepted apply ever touched storage */
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM t5_effect_state") == 1,
          "rejected shapes wrote nothing");
    OK();

    fx_close(&fx);
    return 0;
}

/* ══ 7. precondition truth against REAL storage ════════════════════ */

static int test_precond_storage(void) {
    fixture_t fx;
    CHECK(fx_open(&fx) == 0, "fixture");
    fx.w->v2_runtime_table = g_ext_table;
    fx.w->v2_runtime_table_n = g_ext_n;
    const nodus_domain_runtime_t *rt = lookup_ext(&g_ext_table[2]);
    CHECK(rt != NULL, "T5 resolves");
    struct nodus_witness *W = (struct nodus_witness *)fx.w;

    result_t r;
    uint8_t vb[64];
    int vl = 0;
    uint64_t ver = 0;

    /* CREATE + ABSENT on an absent key */
    CHECK(mk_one(&r, 1, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
                 "pk", "V1", 0, NULL) == 0, "encode create");
    CHECK(nodus_witness_v2_effects_apply(W, rt, &r.view, NULL) ==
          NODUS_ADAPTER_OK, "create on absent -> OK");
    CHECK(row_get(fx.w, T5_DOMAIN, "pk", vb, &vl, &ver) == 1 &&
          vl == 2 && memcmp(vb, "V1", 2) == 0 && ver == 1,
          "row created at version 1");
    OK();

    /* CREATE + ABSENT on a present key */
    uint8_t d0[64], d1[64];
    CHECK(t5_digest(fx.w, d0) == 0, "digest");
    uint16_t fi = 0xFFFF;
    CHECK(nodus_witness_v2_effects_apply(W, rt, &r.view, &fi) ==
          NODUS_ADAPTER_ERR_PRECOND_EXISTS, "create on present -> EXISTS");
    CHECK(fi == 0, "fail index");
    CHECK(t5_digest(fx.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
          "a rejected precondition changed nothing");
    OK();

    /* SET + EXISTS on present, and on absent */
    CHECK(mk_one(&r, 1, DNA_EFFECT_SET, DNA_EFFECT_PRE_EXISTS,
                 "pk", "V2", 0, NULL) == 0, "encode set");
    CHECK(nodus_witness_v2_effects_apply(W, rt, &r.view, NULL) ==
          NODUS_ADAPTER_OK, "set on present -> OK");
    CHECK(row_get(fx.w, T5_DOMAIN, "pk", vb, &vl, &ver) == 1 &&
          vl == 2 && memcmp(vb, "V2", 2) == 0 && ver == 2,
          "value replaced, version incremented");
    CHECK(mk_one(&r, 1, DNA_EFFECT_SET, DNA_EFFECT_PRE_EXISTS,
                 "nope", "V2", 0, NULL) == 0, "encode set-absent");
    CHECK(nodus_witness_v2_effects_apply(W, rt, &r.view, NULL) ==
          NODUS_ADAPTER_ERR_PRECOND_MISSING, "set on absent -> MISSING");
    OK();

    /* DELETE + EXISTS on present, and on absent */
    CHECK(mk_one(&r, 1, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
                 "dk", "D", 0, NULL) == 0, "encode create dk");
    CHECK(nodus_witness_v2_effects_apply(W, rt, &r.view, NULL) ==
          NODUS_ADAPTER_OK, "dk created");
    CHECK(mk_one(&r, 1, DNA_EFFECT_DELETE, DNA_EFFECT_PRE_EXISTS,
                 "dk", NULL, 0, NULL) == 0, "encode delete dk");
    CHECK(r.view.eff[0].value_len == 0, "a DELETE carries no value");
    CHECK(nodus_witness_v2_effects_apply(W, rt, &r.view, NULL) ==
          NODUS_ADAPTER_OK, "delete on present -> OK");
    CHECK(row_get(fx.w, T5_DOMAIN, "dk", NULL, NULL, NULL) == 0,
          "row gone");
    CHECK(nodus_witness_v2_effects_apply(W, rt, &r.view, NULL) ==
          NODUS_ADAPTER_ERR_PRECOND_MISSING, "delete on absent -> MISSING");
    OK();

    /* SET + EXISTS_VERSION, right and wrong */
    CHECK(mk_one(&r, 1, DNA_EFFECT_SET, DNA_EFFECT_PRE_EXISTS_VERSION,
                 "pk", "V3", 2, NULL) == 0, "encode set@2");
    CHECK(nodus_witness_v2_effects_apply(W, rt, &r.view, NULL) ==
          NODUS_ADAPTER_OK, "correct expected_version -> OK");
    CHECK(row_get(fx.w, T5_DOMAIN, "pk", vb, &vl, &ver) == 1 &&
          memcmp(vb, "V3", 2) == 0 && ver == 3, "value + version moved");
    CHECK(t5_digest(fx.w, d0) == 0, "digest");
    CHECK(mk_one(&r, 1, DNA_EFFECT_SET, DNA_EFFECT_PRE_EXISTS_VERSION,
                 "pk", "VX", 99, NULL) == 0, "encode set@99");
    CHECK(nodus_witness_v2_effects_apply(W, rt, &r.view, NULL) ==
          NODUS_ADAPTER_ERR_PRECOND_VERSION,
          "wrong expected_version -> VERSION");
    CHECK(t5_digest(fx.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
          "value unchanged after a version mismatch");
    OK();

    /* SET + EXISTS_VHASH, right and wrong */
    uint8_t vh_cur[64], vh_other[64];
    CHECK(dna_effect_value_hash((const uint8_t *)"V3", 2, vh_cur) == 0 &&
          dna_effect_value_hash((const uint8_t *)"ZZ", 2, vh_other) == 0,
          "value hashes");
    CHECK(memcmp(vh_cur, vh_other, 64) != 0, "the two hashes differ");
    CHECK(mk_one(&r, 1, DNA_EFFECT_SET, DNA_EFFECT_PRE_EXISTS_VHASH,
                 "pk", "V4", 0, vh_other) == 0, "encode set#wrong");
    CHECK(nodus_witness_v2_effects_apply(W, rt, &r.view, NULL) ==
          NODUS_ADAPTER_ERR_PRECOND_HASH, "wrong value hash -> HASH");
    CHECK(t5_digest(fx.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
          "value unchanged after a hash mismatch");
    CHECK(mk_one(&r, 1, DNA_EFFECT_SET, DNA_EFFECT_PRE_EXISTS_VHASH,
                 "pk", "V4", 0, vh_cur) == 0, "encode set#right");
    CHECK(nodus_witness_v2_effects_apply(W, rt, &r.view, NULL) ==
          NODUS_ADAPTER_OK, "correct value hash -> OK");
    CHECK(row_get(fx.w, T5_DOMAIN, "pk", vb, &vl, &ver) == 1 &&
          memcmp(vb, "V4", 2) == 0 && ver == 4, "value replaced");
    OK();

    /* version AND hash together is UNREPRESENTABLE — the codec refuses
     * to encode a reserved field the active tag does not consume */
    dna_effect_in_t e;
    eff_set(&e, 1, DNA_EFFECT_SET, DNA_EFFECT_PRE_EXISTS_VHASH,
            (const uint8_t *)"pk", 2, (const uint8_t *)"V5", 2);
    memcpy(e.hdr.expected_vhash, vh_cur, 64);
    e.hdr.expected_version = 4;
    uint8_t buf[512];
    size_t written = 1;
    CHECK(dna_effect_result_encode(&e, 1, buf, sizeof(buf), &written) != 0 &&
          written == 0,
          "expected_version under EXISTS_VHASH is unencodable");
    OK();

    fx_close(&fx);
    return 0;
}

/* ══ 8. the pure precondition decision matrix ═══════════════════════ */

static int test_precond_eval_matrix(void) {
    uint8_t h_a[64], h_b[64];
    CHECK(dna_effect_value_hash((const uint8_t *)"A", 1, h_a) == 0 &&
          dna_effect_value_hash((const uint8_t *)"B", 1, h_b) == 0,
          "hashes");

    nodus_adapter_row_facts_t absent, present;
    memset(&absent, 0, sizeof(absent));
    absent.exists = 0;
    memset(&present, 0, sizeof(present));
    present.exists = 1;
    present.version = 7;
    memcpy(present.value_hash, h_a, 64);

    /* the seven legal pairs, both existence branches */
    CHECK(nodus_adapter_precond_eval(DNA_EFFECT_CREATE,
              DNA_EFFECT_PRE_ABSENT, 0, NULL, &absent) == NODUS_ADAPTER_OK,
          "CREATE/ABSENT on absent");
    CHECK(nodus_adapter_precond_eval(DNA_EFFECT_CREATE,
              DNA_EFFECT_PRE_ABSENT, 0, NULL, &present) ==
          NODUS_ADAPTER_ERR_PRECOND_EXISTS, "CREATE/ABSENT on present");
    OK();

    const uint8_t kinds[2] = { DNA_EFFECT_SET, DNA_EFFECT_DELETE };
    for (int i = 0; i < 2; i++) {
        uint8_t k = kinds[i];
        CHECK(nodus_adapter_precond_eval(k, DNA_EFFECT_PRE_EXISTS, 0, NULL,
                                         &absent) ==
              NODUS_ADAPTER_ERR_PRECOND_MISSING, "EXISTS on absent");
        CHECK(nodus_adapter_precond_eval(k, DNA_EFFECT_PRE_EXISTS, 0, NULL,
                                         &present) == NODUS_ADAPTER_OK,
              "EXISTS on present");

        CHECK(nodus_adapter_precond_eval(k, DNA_EFFECT_PRE_EXISTS_VERSION,
                                         7, NULL, &absent) ==
              NODUS_ADAPTER_ERR_PRECOND_MISSING,
              "VERSION on absent is MISSING, never VERSION");
        CHECK(nodus_adapter_precond_eval(k, DNA_EFFECT_PRE_EXISTS_VERSION,
                                         7, NULL, &present) ==
              NODUS_ADAPTER_OK, "matching version");
        CHECK(nodus_adapter_precond_eval(k, DNA_EFFECT_PRE_EXISTS_VERSION,
                                         8, NULL, &present) ==
              NODUS_ADAPTER_ERR_PRECOND_VERSION, "version mismatch");
        CHECK(nodus_adapter_precond_eval(k, DNA_EFFECT_PRE_EXISTS_VERSION,
                                         0, NULL, &present) ==
              NODUS_ADAPTER_ERR_PRECOND_VERSION,
              "version 0 does not match version 7");

        CHECK(nodus_adapter_precond_eval(k, DNA_EFFECT_PRE_EXISTS_VHASH,
                                         0, h_a, &absent) ==
              NODUS_ADAPTER_ERR_PRECOND_MISSING,
              "VHASH on absent is MISSING, never HASH");
        CHECK(nodus_adapter_precond_eval(k, DNA_EFFECT_PRE_EXISTS_VHASH,
                                         0, h_a, &present) ==
              NODUS_ADAPTER_OK, "matching value hash");
        CHECK(nodus_adapter_precond_eval(k, DNA_EFFECT_PRE_EXISTS_VHASH,
                                         0, h_b, &present) ==
              NODUS_ADAPTER_ERR_PRECOND_HASH, "value-hash mismatch");
    }
    OK();

    /* exactly seven of the twelve (kind, tag) pairs are legal; every
     * other combination, and every out-of-range value, is FORM */
    int legal = 0;
    for (uint8_t k = 1; k <= 3; k++) {
        for (uint8_t t = 1; t <= 4; t++) {
            nodus_adapter_status_t st =
                nodus_adapter_precond_eval(k, t, 0, h_a, &absent);
            if (st != NODUS_ADAPTER_ERR_PRECOND_FORM) legal++;
        }
    }
    CHECK(legal == 7, "exactly seven legal (kind, tag) pairs");
    CHECK(nodus_adapter_precond_eval(DNA_EFFECT_CREATE,
              DNA_EFFECT_PRE_EXISTS, 0, h_a, &absent) ==
          NODUS_ADAPTER_ERR_PRECOND_FORM, "CREATE/EXISTS illegal");
    CHECK(nodus_adapter_precond_eval(DNA_EFFECT_SET,
              DNA_EFFECT_PRE_ABSENT, 0, h_a, &absent) ==
          NODUS_ADAPTER_ERR_PRECOND_FORM, "SET/ABSENT illegal");
    CHECK(nodus_adapter_precond_eval(DNA_EFFECT_DELETE,
              DNA_EFFECT_PRE_ABSENT, 0, h_a, &absent) ==
          NODUS_ADAPTER_ERR_PRECOND_FORM, "DELETE/ABSENT illegal");
    CHECK(nodus_adapter_precond_eval(0, DNA_EFFECT_PRE_ABSENT, 0, h_a,
                                     &absent) ==
          NODUS_ADAPTER_ERR_PRECOND_FORM, "kind 0 illegal");
    CHECK(nodus_adapter_precond_eval(4, DNA_EFFECT_PRE_EXISTS, 0, h_a,
                                     &absent) ==
          NODUS_ADAPTER_ERR_PRECOND_FORM, "kind 4 illegal");
    CHECK(nodus_adapter_precond_eval(DNA_EFFECT_SET, 0, 0, h_a, &absent) ==
          NODUS_ADAPTER_ERR_PRECOND_FORM, "tag 0 illegal");
    CHECK(nodus_adapter_precond_eval(DNA_EFFECT_SET, 5, 0, h_a, &absent) ==
          NODUS_ADAPTER_ERR_PRECOND_FORM, "tag 5 illegal");
    OK();

    /* an out-of-contract FACT VALUE is a broken compiled adapter on THIS
     * node — a node-local STORAGE FAULT, never an argument error and
     * never a verdict (either existence branch would manufacture one) */
    nodus_adapter_row_facts_t weird = present;
    weird.exists = 2;
    CHECK(nodus_adapter_precond_eval(DNA_EFFECT_CREATE,
              DNA_EFFECT_PRE_ABSENT, 0, NULL, &weird) ==
          NODUS_ADAPTER_ERR_STORAGE_FAULT, "exists == 2 -> STORAGE_FAULT");
    weird.exists = -1;
    CHECK(nodus_adapter_precond_eval(DNA_EFFECT_SET,
              DNA_EFFECT_PRE_EXISTS, 0, NULL, &weird) ==
          NODUS_ADAPTER_ERR_STORAGE_FAULT, "exists == -1 -> STORAGE_FAULT");
    CHECK(nodus_adapter_precond_eval(DNA_EFFECT_SET,
              DNA_EFFECT_PRE_EXISTS, 0, NULL, NULL) ==
          NODUS_ADAPTER_ERR_ARG, "NULL facts -> ERR_ARG");
    CHECK(nodus_adapter_precond_eval(DNA_EFFECT_SET,
              DNA_EFFECT_PRE_EXISTS_VHASH, 0, NULL, &present) ==
          NODUS_ADAPTER_ERR_ARG, "VHASH without a hash -> ERR_ARG");
    OK();

    return 0;
}

/* ══ 9. fault vs verdict ════════════════════════════════════════════ */

static int test_storage_fault(void) {
    fixture_t fx;
    CHECK(fx_open(&fx) == 0, "fixture");
    fx.w->v2_runtime_table = g_ext_table;
    fx.w->v2_runtime_table_n = g_ext_n;
    const nodus_domain_runtime_t *rt = lookup_ext(&g_ext_table[2]);
    CHECK(rt != NULL, "T5 resolves");
    struct nodus_witness *W = (struct nodus_witness *)fx.w;

    result_t r;
    CHECK(mk_one(&r, 1, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
                 "fk", "F", 0, NULL) == 0, "encode");

    CHECK(run_sql(fx.w->db, "DROP TABLE t5_effect_state") == 0, "drop table");
    uint16_t fi = 0xFFFF;
    nodus_adapter_status_t st =
        nodus_witness_v2_effects_apply(W, rt, &r.view, &fi);
    CHECK(st == NODUS_ADAPTER_ERR_STORAGE_FAULT,
          "a dropped table is a STORAGE FAULT");
    CHECK(st != NODUS_ADAPTER_ERR_PRECOND_MISSING,
          "a fault is NEVER an absent row");
    CHECK(st != NODUS_ADAPTER_OK, "a fault is NEVER an accept");
    CHECK(fi == 0, "the faulting effect's index");
    OK();

    /* THE load-bearing distinction: a SET against faulted storage. A
     * layer that collapsed the probe's fault into "the row is absent"
     * would answer ERR_PRECOND_MISSING here — a transaction verdict
     * manufactured out of a node fault, exactly the chain-split shape
     * this boundary exists to prevent. (The CREATE above cannot pin
     * this alone: even a collapsing layer would still fault in its
     * MUTATE step, so only a row-requiring precondition separates the
     * two behaviours.) */
    result_t rs;
    CHECK(mk_one(&rs, 1, DNA_EFFECT_SET, DNA_EFFECT_PRE_EXISTS,
                 "fk", "S", 0, NULL) == 0, "encode set");
    st = nodus_witness_v2_effects_apply(W, rt, &rs.view, NULL);
    CHECK(st == NODUS_ADAPTER_ERR_STORAGE_FAULT,
          "a faulted probe on a SET is a STORAGE FAULT");
    CHECK(st != NODUS_ADAPTER_ERR_PRECOND_MISSING,
          "and NEVER a missing-row verdict");
    OK();

    /* validate is untouched by storage, so it still says OK — the shape
     * was never the problem */
    CHECK(nodus_witness_v2_effects_validate(rt, &r.view, NULL) ==
          NODUS_ADAPTER_OK, "validate is storage-independent");
    OK();

    /* an OUT-OF-CONTRACT probe status is COERCED to a storage fault: a
     * rogue probe answering ERR_PRECOND_MISSING must never surface as a
     * precondition verdict — the shipped decision table is the ONLY
     * origin of those */
    {
        nodus_domain_adapter_t rogue = T5_ADAPTER;
        rogue.probe = rogue_probe;
        nodus_domain_runtime_t rogue_rt = g_ext_table[2];
        rogue_rt.adapter = &rogue;
        nodus_adapter_status_t rst =
            nodus_witness_v2_effects_apply(W, &rogue_rt, &r.view, NULL);
        CHECK(rst == NODUS_ADAPTER_ERR_STORAGE_FAULT,
              "rogue probe status coerced to STORAGE_FAULT");
        CHECK(rst != NODUS_ADAPTER_ERR_PRECOND_MISSING,
              "a rogue precondition status never escapes");
    }
    OK();

    /* the fault was the table, not the effect */
    CHECK(run_sql(fx.w->db, T5_TABLE_SQL) == 0, "recreate table");
    CHECK(nodus_witness_v2_effects_apply(W, rt, &r.view, NULL) ==
          NODUS_ADAPTER_OK, "the same effect applies once storage is back");
    CHECK(row_get(fx.w, T5_DOMAIN, "fk", NULL, NULL, NULL) == 1,
          "row landed");
    OK();

    fx_close(&fx);
    return 0;
}

/* ══ 10. failure contract + caller rollback ════════════════════════ */

static int test_failure_contract(void) {
    fixture_t fx;
    CHECK(fx_open(&fx) == 0, "fixture");
    fx.w->v2_runtime_table = g_ext_table;
    fx.w->v2_runtime_table_n = g_ext_n;
    const nodus_domain_runtime_t *rt = lookup_ext(&g_ext_table[2]);
    CHECK(rt != NULL, "T5 resolves");
    struct nodus_witness *W = (struct nodus_witness *)fx.w;

    /* pre-seed the key the THIRD effect will collide with */
    result_t seed;
    CHECK(mk_one(&seed, 1, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
                 "ec", "seed", 0, NULL) == 0, "encode seed");
    CHECK(nodus_witness_v2_effects_apply(W, rt, &seed.view, NULL) ==
          NODUS_ADAPTER_OK, "seed applied");

    uint8_t before[64], after[64];
    CHECK(t5_digest(fx.w, before) == 0, "digest before");

    const uint8_t ka[2] = { 'e', 'a' };
    const uint8_t kb[2] = { 'e', 'b' };
    const uint8_t kc[2] = { 'e', 'c' };
    const uint8_t val[1] = { 'x' };
    dna_effect_in_t ins[3];
    eff_set(&ins[0], 1, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
            ka, 2, val, 1);
    eff_set(&ins[1], 1, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
            kb, 2, val, 1);
    eff_set(&ins[2], 1, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
            kc, 2, val, 1);
    result_t r;
    CHECK(mk_result(ins, 3, &r) == 0, "encode 3 effects");
    CHECK(r.view.effect_count == 3, "three effects, canonical order");

    /* the CALLER owns the transaction — this layer never opens one */
    CHECK(run_sql(fx.w->db, "BEGIN") == 0, "caller BEGIN");
    uint16_t fi = 0xFFFF;
    CHECK(nodus_witness_v2_effects_apply(W, rt, &r.view, &fi) ==
          NODUS_ADAPTER_ERR_PRECOND_EXISTS, "effect 2 fails its precondition");
    CHECK(fi == 2, "fail_index == 2");
    OK();

    /* effects 0-1 are visible pre-rollback: the layer applied in
     * canonical order and stopped at the first failure */
    CHECK(row_get(fx.w, T5_DOMAIN, "ea", NULL, NULL, NULL) == 1,
          "effect 0 applied");
    CHECK(row_get(fx.w, T5_DOMAIN, "eb", NULL, NULL, NULL) == 1,
          "effect 1 applied");
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM t5_effect_state") == 3,
          "seed + two partial rows");
    OK();

    CHECK(run_sql(fx.w->db, "ROLLBACK") == 0, "caller ROLLBACK");
    CHECK(t5_digest(fx.w, after) == 0, "digest after");
    CHECK(memcmp(before, after, 64) == 0,
          "the caller's rollback restored the table byte-for-byte");
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM t5_effect_state") == 1,
          "only the seed row remains");
    OK();

    fx_close(&fx);
    return 0;
}

/* ══ 11. purity, arguments, and the EMPTY result ═══════════════════ */

static int test_purity_and_args(void) {
    fixture_t fx;
    CHECK(fx_open(&fx) == 0, "fixture");
    fx.w->v2_runtime_table = g_ext_table;
    fx.w->v2_runtime_table_n = g_ext_n;
    const nodus_domain_runtime_t *rt = lookup_ext(&g_ext_table[2]);
    CHECK(rt != NULL, "T5 resolves");
    struct nodus_witness *W = (struct nodus_witness *)fx.w;

    result_t r;
    CHECK(mk_one(&r, 1, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
                 "pure", "p", 0, NULL) == 0, "encode");
    CHECK(nodus_witness_v2_effects_apply(W, rt, &r.view, NULL) ==
          NODUS_ADAPTER_OK, "first apply");

    /* VALIDATE IS PURE: the same result would now fail its precondition,
     * and validate still says OK because it judges SHAPE only */
    uint8_t d0[64], d1[64];
    int probes = g_probe_calls;
    CHECK(t5_digest(fx.w, d0) == 0, "digest");
    CHECK(nodus_witness_v2_effects_validate(rt, &r.view, NULL) ==
          NODUS_ADAPTER_OK, "validate ignores state");
    CHECK(t5_digest(fx.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
          "validate wrote nothing");
    CHECK(g_probe_calls == probes, "validate did not even probe");
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM t5_effect_state") == 1,
          "row count unchanged");
    OK();

    /* a rejected/zeroed view is told apart from an empty result by `buf`,
     * never by the count */
    dna_effect_view_t zero;
    memset(&zero, 0, sizeof(zero));
    CHECK(zero.effect_count == 0 && zero.buf == NULL, "zeroed view shape");
    CHECK(nodus_witness_v2_effects_validate(rt, &zero, NULL) ==
          NODUS_ADAPTER_ERR_ARG, "zeroed view -> ERR_ARG (validate)");
    CHECK(nodus_witness_v2_effects_apply(W, rt, &zero, NULL) ==
          NODUS_ADAPTER_ERR_ARG, "zeroed view -> ERR_ARG (apply)");
    /* and a genuinely rejected decode produces exactly that view */
    uint8_t junk[DNA_EFFECT_FIXED_HEAD];
    memset(junk, 0xAA, sizeof(junk));
    dna_effect_view_t rejected;
    memset(&rejected, 0x11, sizeof(rejected));
    CHECK(dna_effect_result_decode(junk, sizeof(junk), &rejected) != 0,
          "junk does not decode");
    CHECK(rejected.buf == NULL && rejected.effect_count == 0,
          "a rejected decode zeroes the view");
    CHECK(nodus_witness_v2_effects_validate(rt, &rejected, NULL) ==
          NODUS_ADAPTER_ERR_ARG, "rejected view -> ERR_ARG");
    OK();

    /* DEFENCE IN DEPTH on the view's geometry: a decode-produced view is
     * in-bounds by construction, but validate is callable directly, and
     * apply dereferences the offsets — so a view whose blob windows
     * stray outside its declared buffer must die in validate as ERR_ARG
     * (the env_wire view_slice_ok discipline). */
    {
        result_t rg;
        CHECK(mk_one(&rg, 1, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
                     "geo", "g", 0, NULL) == 0, "encode");
        uint16_t gfi = 0xFFFF;
        uint32_t saved = rg.view.key_off[0];
        rg.view.key_off[0] = (uint32_t)rg.view.res_len;   /* one past end */
        CHECK(nodus_witness_v2_effects_validate(rt, &rg.view, &gfi) ==
              NODUS_ADAPTER_ERR_ARG, "key window past the buffer");
        CHECK(gfi == 0, "failing effect index");
        rg.view.key_off[0] = saved;
        rg.view.val_off[0] = 0x40000000u;                 /* wild offset */
        CHECK(nodus_witness_v2_effects_validate(rt, &rg.view, NULL) ==
              NODUS_ADAPTER_ERR_ARG, "value window outside the buffer");
        /* and the untouched view still validates */
        CHECK(mk_one(&rg, 1, DNA_EFFECT_CREATE, DNA_EFFECT_PRE_ABSENT,
                     "geo", "g", 0, NULL) == 0, "re-encode");
        CHECK(nodus_witness_v2_effects_validate(rt, &rg.view, NULL) ==
              NODUS_ADAPTER_OK, "pristine view validates");
    }
    OK();

    /* validate is complete on the FORM axis: a hand-mutated (SET, ABSENT)
     * pair — unencodable through the codec — dies in validate as
     * ERR_PRECOND_FORM, BEFORE apply could probe storage */
    {
        result_t rp;
        CHECK(mk_one(&rp, 1, DNA_EFFECT_SET, DNA_EFFECT_PRE_EXISTS,
                     "form", "f", 0, NULL) == 0, "encode SET+EXISTS");
        rp.view.eff[0].precond_tag = (uint8_t)DNA_EFFECT_PRE_ABSENT;
        int probes2 = g_probe_calls;
        CHECK(nodus_witness_v2_effects_validate(rt, &rp.view, NULL) ==
              NODUS_ADAPTER_ERR_PRECOND_FORM,
              "hand-built (SET, ABSENT) dies in validate");
        CHECK(nodus_witness_v2_effects_apply(W, rt, &rp.view, NULL) ==
              NODUS_ADAPTER_ERR_PRECOND_FORM, "and in apply's validate");
        CHECK(g_probe_calls == probes2, "storage was never probed");
    }
    OK();

    /* the argument matrix */
    uint16_t fi = 0xFFFF;
    CHECK(nodus_witness_v2_effects_validate(NULL, &r.view, &fi) ==
          NODUS_ADAPTER_ERR_ARG, "NULL rt (validate)");
    CHECK(fi == 0, "index 0 on a result-level reject");
    CHECK(nodus_witness_v2_effects_validate(rt, NULL, NULL) ==
          NODUS_ADAPTER_ERR_ARG, "NULL view (validate)");
    CHECK(nodus_witness_v2_effects_apply(W, NULL, &r.view, NULL) ==
          NODUS_ADAPTER_ERR_ARG, "NULL rt (apply)");
    CHECK(nodus_witness_v2_effects_apply(W, rt, NULL, NULL) ==
          NODUS_ADAPTER_ERR_ARG, "NULL view (apply)");
    CHECK(nodus_witness_v2_effects_apply(NULL, rt, &r.view, NULL) ==
          NODUS_ADAPTER_ERR_ARG, "NULL witness (apply)");
    OK();

    /* the EMPTY result: valid, applies, mutates nothing */
    uint8_t empty[DNA_EFFECT_FIXED_HEAD];
    size_t written = 0;
    CHECK(dna_effect_result_encode(NULL, 0, empty, sizeof(empty),
                                   &written) == 0 &&
          written == DNA_EFFECT_FIXED_HEAD, "empty result encodes to 23 B");
    dna_effect_view_t ev;
    CHECK(dna_effect_result_decode(empty, written, &ev) == 0,
          "empty result decodes");
    CHECK(ev.effect_count == 0 && ev.buf != NULL,
          "an ACCEPTED empty result has buf != NULL");
    int mutates = g_mutate_calls;
    CHECK(t5_digest(fx.w, d0) == 0, "digest");
    CHECK(nodus_witness_v2_effects_validate(rt, &ev, NULL) ==
          NODUS_ADAPTER_OK, "empty validates vacuously");
    CHECK(nodus_witness_v2_effects_apply(W, rt, &ev, NULL) ==
          NODUS_ADAPTER_OK, "empty applies");
    CHECK(g_mutate_calls == mutates, "zero mutations");
    CHECK(t5_digest(fx.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
          "storage untouched by an empty result");
    OK();

    fx_close(&fx);
    return 0;
}

/* ── main ───────────────────────────────────────────────────────────── */

/* ── the mediated-read boundary (nodus_witness_v2_read_one) ────────── */
static int test_mediated_read(void) {
    fixture_t fx;
    CHECK(fx_open(&fx) == 0, "fixture");
    fx.w->v2_runtime_table = g_ext_table;
    fx.w->v2_runtime_table_n = g_ext_n;
    const nodus_domain_runtime_t *rt = lookup_ext(&g_ext_table[2]);
    CHECK(rt != NULL, "T5 resolves");
    struct nodus_witness *W = (struct nodus_witness *)fx.w;

    /* seed one row IN T5's domain and a decoy in T6's */
    CHECK(run_sql(fx.w->db,
          "INSERT INTO t5_effect_state (domain_id, k, v, version) "
          "VALUES (11, x'aa', x'0102', 1)") == 0, "seed");
    CHECK(run_sql(fx.w->db,
          "INSERT INTO t5_effect_state (domain_id, k, v, version) "
          "VALUES (13, x'ab', x'ff', 1)") == 0, "decoy");

    nodus_rt_read_req_t req;
    memset(&req, 0, sizeof(req));
    req.op_id = 1;
    req.key_len = 1;
    req.key[0] = 0xAA;
    nodus_rt_read_res_t *res = malloc(sizeof(*res));
    CHECK(res != NULL, "alloc");

    /* PRESENT: value copied whole */
    CHECK(nodus_witness_v2_read_one(W, rt, &req, res) ==
          NODUS_ADAPTER_OK, "present read");
    CHECK(res->present == 1 && res->value_len == 2 &&
          res->value[0] == 0x01 && res->value[1] == 0x02,
          "present read value"); OK();

    /* MISSING: a SUCCESSFUL read of an absent key — never a fault */
    req.key[0] = 0xBB;
    CHECK(nodus_witness_v2_read_one(W, rt, &req, res) ==
          NODUS_ADAPTER_OK, "missing read");
    CHECK(res->present == 0 && res->value_len == 0, "missing shape");
    OK();

    /* DOMAIN SCOPE: T6's row is invisible through T5's runtime — the
     * authoritative domain is rt->domain_id, nothing else */
    req.key[0] = 0xAB;
    CHECK(nodus_witness_v2_read_one(W, rt, &req, res) ==
          NODUS_ADAPTER_OK && res->present == 0,
          "cross-domain row leaked through a read"); OK();

    /* UNKNOWN OP + key bounds */
    req.op_id = 7;
    req.key[0] = 0xAA;
    CHECK(nodus_witness_v2_read_one(W, rt, &req, res) ==
          NODUS_ADAPTER_ERR_UNKNOWN_OP, "unknown op resolves"); OK();
    req.op_id = 2;                       /* narrow op: key 8..8          */
    req.key_len = 1;
    CHECK(nodus_witness_v2_read_one(W, rt, &req, res) ==
          NODUS_ADAPTER_ERR_SHAPE, "key below the op floor"); OK();
    req.op_id = 1;
    req.key_len = 0;
    CHECK(nodus_witness_v2_read_one(W, rt, &req, res) ==
          NODUS_ADAPTER_ERR_SHAPE, "zero-length key"); OK();
    req.key_len = 1;

    /* NO read fn: fail closed, never "absent" */
    {
        nodus_domain_adapter_t noread = T5_ADAPTER;
        noread.read = NULL;
        nodus_domain_runtime_t rt2 = *rt;
        rt2.adapter = &noread;
        CHECK(nodus_witness_v2_read_one(W, &rt2, &req, res) ==
              NODUS_ADAPTER_ERR_NO_ADAPTER, "no read fn fails closed");
        OK();
    }
    /* ROGUE status + LYING facts: both coerced to STORAGE FAULT */
    {
        nodus_domain_adapter_t bad = T5_ADAPTER;
        bad.read = rogue_read;
        nodus_domain_runtime_t rt2 = *rt;
        rt2.adapter = &bad;
        CHECK(nodus_witness_v2_read_one(W, &rt2, &req, res) ==
              NODUS_ADAPTER_ERR_STORAGE_FAULT, "rogue status coerced");
        bad.read = lying_read;
        CHECK(nodus_witness_v2_read_one(W, &rt2, &req, res) ==
              NODUS_ADAPTER_ERR_STORAGE_FAULT, "lying facts coerced");
        CHECK(res->present == 0 && res->value_len == 0,
              "failed read published bytes"); OK();
    }
    /* STORAGE FAULT: dropped table — and NEVER an absent row */
    CHECK(run_sql(fx.w->db, "DROP TABLE t5_effect_state") == 0, "drop");
    CHECK(nodus_witness_v2_read_one(W, rt, &req, res) ==
          NODUS_ADAPTER_ERR_STORAGE_FAULT, "fault is a FAULT");
    CHECK(res->present == 0 && res->value_len == 0,
          "faulted read left bytes"); OK();

    free(res);
    fx_close(&fx);
    return 0;
}

int main(void) {
    if (ext_table_init() != 0) {
        fprintf(stderr, "ext_table_init failed\n");
        return 1;
    }
    if (test_mediated_read()) return 1;
    if (test_adapter_authority()) return 1;
    if (test_end_to_end_registry()) return 1;
    if (test_domain_authority()) return 1;
    if (test_injection_is_opaque()) return 1;
    if (test_selfcheck_matrix()) return 1;
    if (test_op_restrictions()) return 1;
    if (test_precond_storage()) return 1;
    if (test_precond_eval_matrix()) return 1;
    if (test_storage_fault()) return 1;
    if (test_failure_contract()) return 1;
    if (test_purity_and_args()) return 1;

    printf("test_v2_effects: ALL PASS (%d checks)\n", g_checks);
    return 0;
}
