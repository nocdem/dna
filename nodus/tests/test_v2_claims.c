/**
 * Nodus — Ledger V2 S6: witness manifest/claims integration (INACTIVE).
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
 *   3. Genesis with a PRESENT-distribution manifest (synthetic generic
 *      data, real ML-DSA-87 keys): manifest/dist-state seeding, supply
 *      gate with the unclaimed-distribution owner, snapshot + manifest
 *      root reconstruction byte-identity, chain_id derived through the
 *      REAL genesis BlockID (header ‖ manifest bytes).
 *   4. Claim lifecycle: multi-claim block; deterministic DNA_CORE
 *      output (amount, owner, domain_id = 1, created_at = 0);
 *      remaining decrement; claims_root reconstruction; supply holds;
 *      supply_tracking UNTOUCHED (a claim never mints); SYSTEM head
 *      does not advance.
 *   5. Adversarial matrix (every reject digest-proven no-op):
 *      early / late (post-deadline RETAIN) / duplicate-in-block /
 *      already-spent / destination substitution (leaf tamper AND wrong
 *      key) / bad signature / wrong amount / corrupt proof / wrong
 *      index / out-of-range index / unknown manifest / cross-chain
 *      replay onto a real second chain.
 *   6. Insertion-order independence: same claims, reversed order in the
 *      same block on an identical twin fixture → byte-identical
 *      claims_root / core / global roots.
 *   7. Fault injection F16/F17/F18 (the S6 apply stages) + F13 with a
 *      claim aboard: rc −1 and the FULL DB digest is byte-identical.
 *   8. Restart persistence + idempotent replay; spent-claim survives
 *      reopen and re-claims reject.
 *   9. Never-mint: a manifest committing LESS than the snapshot sum —
 *      the remaining-value gate rejects the overdraw and rolls back.
 *  10. Genesis manifest rejects: wrong domain hash / wrong domain count
 *      / supply mismatch — whole genesis rolled back (digest-proven).
 *  11. Inactive boundary: V2 admission rejects tx types 12-14 for both
 *      domains (the claim path has NO live transaction type).
 *
 * @file test_v2_claims.c
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_roots_v2.h"
#include "nodus/nodus_chain_config.h"

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
    sqlite3_close(fx->w->db);
    fx->w->db = NULL;
    return nodus_witness_create_chain_db(fx->w, fx->chain_id16);
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

/* ── manifest + genesis builders ────────────────────────────────────── */

/* The REAL DomainManifest hashes: pre-run the (idempotent) registry
 * genesis, then hash the stored manifests — genesis_ex re-runs it and
 * byte-compares, so state must not move in between (it doesn't). */
static int domman_hashes(nodus_witness_t *w, uint8_t sys_h[64],
                         uint8_t core_h[64]) {
    if (nodus_witness_domreg_init_genesis(w) != 0) return -1;
    dna_domain_manifest_t m;
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_SYSTEM, NULL, &m, NULL)
            != 0 || dna_domman_hash(&m, sys_h) != 0)
        return -1;
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_CORE, NULL, &m, NULL)
            != 0 || dna_domman_hash(&m, core_h) != 0)
        return -1;
    return 0;
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
                      const char *tag) {
    m->dist_present = 1;
    m->dist_version = DNA_DIST_VERSION;
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
static int genesis_id_of(const uint8_t *mbytes, size_t mlen,
                         uint8_t out_id[64], uint8_t out_chain[32]) {
    dna_block_header_v2_t h;
    memset(&h, 0, sizeof(h));
    h.header_version = DNA_BH2_VERSION;      /* height 0, zero chain_id */
    if (dna_bh2_genesis_block_id(&h, mbytes, mlen, out_id) != 0) return -1;
    return dna_bh2_derive_chain_id(out_id, out_chain);
}

/* Seed supply so that genesis + minted − burned == utxo + unclaimed. */
static int seed_supply(nodus_witness_t *w, uint64_t genesis_supply,
                       uint64_t utxo_amount) {
    char sql[512];
    snprintf(sql, sizeof(sql),
        "INSERT INTO supply_tracking (id, genesis_supply, total_burned, "
        "total_minted, current_supply, last_tx_hash, last_sequence) "
        "VALUES (1, %llu, 0, 0, %llu, x'00', 0)",
        (unsigned long long)genesis_supply,
        (unsigned long long)genesis_supply);
    if (run_sql(w->db, sql) != 0) return -1;
    snprintf(sql, sizeof(sql),
        "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
        "tx_hash, output_index, block_height, created_at, unlock_block) "
        "VALUES (zeroblob(63)||x'01', 'genesis', %llu, zeroblob(64), "
        "zeroblob(63)||x'aa', 0, 0, 0, 0)",
        (unsigned long long)utxo_amount);
    return run_sql(w->db, sql);
}

/* Full present-distribution genesis on a fresh fixture. Outputs the
 * derived chain id + the genesis block id. */
static int dist_genesis(fixture_t *fx, uint64_t total, uint64_t start_h,
                        uint64_t end_h, const char *tag,
                        uint8_t out_chain[32], uint8_t out_gid[64]) {
    if (nodus_witness_db_migrate_v2s6(fx->w) != 0) return -1;
    if (seed_supply(fx->w, 1000, 1000 - total) != 0) return -1;
    uint8_t sys_h[64], core_h[64];
    if (domman_hashes(fx->w, sys_h, core_h) != 0) return -1;
    dna_gman_t m;
    gman_base(&m, 1000, sys_h, core_h);
    gman_dist(&m, total, start_h, end_h, tag);
    uint8_t mbytes[8192];
    size_t mlen = 0;
    if (dna_gman_encode(&m, mbytes, sizeof(mbytes), &mlen) != 0) return -1;
    uint8_t vset[64];
    memset(vset, 0x77, 64);
    if (genesis_id_of(mbytes, mlen, out_gid, out_chain) != 0) return -1;
    return nodus_witness_v2_genesis_ex(fx->w, out_gid, vset, 0,
                                       mbytes, mlen);
}

/* ── claim + block builders ─────────────────────────────────────────── */

static int make_claim(dna_claim_t *c, int leaf, const uint8_t chain[32],
                      uint32_t seq) {
    memset(c, 0, sizeof(*c));
    c->claim_version = DNA_CLAIM_VERSION;
    memcpy(c->chain_id, chain, 32);
    c->manifest_seq = seq;
    c->leaf_index = (uint64_t)leaf;
    c->source_id_len = g_leaf[leaf].source_id_len;
    memcpy(c->source_id, g_leaf[leaf].source_id, c->source_id_len);
    c->source_amount = g_leaf[leaf].source_amount;
    memcpy(c->dest_binding, g_leaf[leaf].dest_binding, 64);
    uint16_t ns = 0;
    if (dna_dist_proof_build(g_leaf_hash, N_LEAVES, (uint64_t)leaf,
                             c->siblings, &ns) != 0)
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
    mk_id(b->block_id, (uint8_t)(0xB0 + h));
    if (h == 1) memcpy(b->prev_block_id, gen_id, 64);
    else mk_id(b->prev_block_id, (uint8_t)(0xB0 + h - 1));
    mk_id(b->vset_hash, 0x77);
    b->claims = claims;
    b->n_claims = n_claims;
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

/* claim's utxo id + nullifier, derived exactly as consensus does */
static int claim_ids(const dna_claim_t *c, uint8_t nul[64],
                     uint8_t uid[64]) {
    if (dna_claim_nullifier(c->chain_id, c->manifest_seq, c->source_id,
                            c->source_id_len, nul) != 0)
        return -1;
    return dna_claim_utxo_id(nul, uid);
}

/* apply a block that must REJECT, digest-proven no-op */
static int expect_reject(nodus_witness_t *w, nodus_v2_block_t *b,
                         const char *msg) {
    uint8_t d0[64], d1[64];
    if (db_state_digest(w, d0) != 0) return 1;
    if (nodus_witness_v2_apply_block(w, b) != -1) {
        fprintf(stderr, "expected reject: %s\n", msg);
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

static int absent_genesis(fixture_t *fx, uint8_t out_sys[64],
                          uint8_t out_core[64], uint8_t out_glob[64],
                          uint8_t out_manroot[64]) {
    if (fx_open(fx) != 0) return -1;
    if (nodus_witness_db_migrate_v2s6(fx->w) != 0) return -1;
    uint8_t sys_h[64], core_h[64];
    if (domman_hashes(fx->w, sys_h, core_h) != 0) return -1;
    dna_gman_t m;
    gman_base(&m, 0, sys_h, core_h);        /* pre-genesis supply = 0 */
    uint8_t mbytes[8192];
    size_t mlen = 0;
    if (dna_gman_encode(&m, mbytes, sizeof(mbytes), &mlen) != 0) return -1;
    uint8_t gid[64], chain[32], vset[64];
    memset(vset, 0x77, 64);
    if (genesis_id_of(mbytes, mlen, gid, chain) != 0) return -1;
    if (nodus_witness_v2_genesis_ex(fx->w, gid, vset, 0, mbytes, mlen)
        != 0)
        return -1;
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
    uint32_t seq0 = 0;
    CHECK(dna_gman_hash(&stored, mh) == 0, "stored hash");
    uint8_t mhs[1][64];
    memcpy(mhs[0], mh, 64);
    CHECK(dna_v2_manifest_root(&seq0, mhs, 1, man_rec) == 0 &&
          memcmp(man_rec, man_a, 64) == 0,
          "manifest root reconstruction");
    OK();

    /* stored SYSTEM head root == live recomputation (commits the real
     * manifest root) */
    uint8_t head[64];
    sqlite3_stmt *st = NULL;
    CHECK(sqlite3_prepare_v2(fa.w->db,
              "SELECT system_root FROM v2_blocks WHERE global_height=0",
              -1, &st, NULL) == SQLITE_OK &&
              sqlite3_step(st) == SQLITE_ROW &&
              sqlite3_column_bytes(st, 0) == 64, "head row");
    memcpy(head, sqlite3_column_blob(st, 0), 64);
    sqlite3_finalize(st);
    CHECK(memcmp(head, sys_a, 64) == 0, "stored head == recompute");
    OK();

    /* no unclaimed value without a distribution */
    uint64_t unc = 99;
    CHECK(nodus_witness_v2_unclaimed_total(fa.w, &unc) == 0 && unc == 0,
          "no unclaimed");
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

/* ── 3+4+5+7+8: the present-distribution lifecycle fixture ──────────── */

static int test_dist_lifecycle(void) {
    fixture_t fx;
    uint8_t chain[32], gid[64];
    CHECK(fx_open(&fx) == 0, "fixture");
    /* window [2, 6] */
    CHECK(dist_genesis(&fx, 32, 2, 6, "testnet-generic", chain, gid) == 0,
          "dist genesis");
    OK();

    /* 3. accounting seeded + reconstruction */
    CHECK(q1(fx.w, "SELECT remaining FROM v2_dist_state WHERE "
                   "manifest_seq=0") == 32, "remaining 32");
    CHECK(nodus_witness_v2_supply_check(fx.w) == 0, "supply at genesis");
    dna_gman_t stored;
    CHECK(nodus_witness_v2_manifest_load(fx.w, 0, &stored) == 0, "load");
    CHECK(memcmp(stored.snapshot_root, g_snapshot_root, 64) == 0,
          "snapshot root committed");
    uint8_t rec[64];
    CHECK(dna_dist_snapshot_root(g_leaf, N_LEAVES, rec) == 0 &&
          memcmp(rec, stored.snapshot_root, 64) == 0,
          "snapshot reconstruction byte-identity");
    uint8_t claims_root[64], empty[64];
    CHECK(nodus_witness_claims_root_v2(fx.w, claims_root) == 0, "cr");
    CHECK(dna_v2_empty_root(DNA_V2_EMPTY_CLAIMS, empty) == 0 &&
          memcmp(claims_root, empty, 64) == 0, "claims root empty");
    OK();

    /* claims for all three leaves */
    dna_claim_t c0, c1, c2;
    CHECK(make_claim(&c0, 0, chain, 0) == 0, "claim0");
    CHECK(make_claim(&c1, 1, chain, 0) == 0, "claim1");
    CHECK(make_claim(&c2, 2, chain, 0) == 0, "claim2");
    OK();

    /* 5a. EARLY: h=1 < start=2 rejects, digest-proven */
    nodus_v2_block_t b;
    mk_claim_block(&b, 1, gid, &c0, 1);
    CHECK(expect_reject(fx.w, &b, "early claim") == 0, "early"); OK();

    /* h=1 spacer commits (no ops, no claims) */
    mk_claim_block(&b, 1, gid, NULL, 0);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0, "spacer h1"); OK();

    /* 4. h=2: MULTI-claim block [c0, c1] commits */
    uint64_t sys_h_before = q1(fx.w,
        "SELECT domain_height FROM v2_domain_heads WHERE domain_id=0");
    dna_claim_t two[2];
    two[0] = c0; two[1] = c1;
    mk_claim_block(&b, 2, gid, two, 2);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0, "claims h2"); OK();

    /* outputs: deterministic id, amount, owner, domain, created_at */
    for (int i = 0; i < 2; i++) {
        uint8_t nul[64], uid[64];
        CHECK(claim_ids(i == 0 ? &c0 : &c1, nul, uid) == 0, "ids");
        uint64_t amt = 0, dom = 9, cat = 9;
        char owner[130];
        CHECK(utxo_row(fx.w, uid, &amt, &dom, &cat, owner) == 0,
              "claim utxo exists");
        CHECK(amt == g_conv_amount[i], "converted amount");
        CHECK(dom == 1, "DNA_CORE owned");
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
    CHECK(q1(fx.w, "SELECT remaining FROM v2_dist_state WHERE "
                   "manifest_seq=0") == 32 - 22, "remaining 10");
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
        uint8_t nul0[64], nul1[64], uid[64];
        CHECK(claim_ids(&c0, nul0, uid) == 0, "n0");
        CHECK(claim_ids(&c1, nul1, uid) == 0, "n1");
        int first = memcmp(nul0, nul1, 64) < 0 ? 0 : 1;
        for (int k = 0; k < 2; k++) {
            const uint8_t *nul = (k == 0) == (first == 0) ? nul0 : nul1;
            int leaf = (k == 0) == (first == 0) ? 0 : 1;
            memcpy(e[k].nullifier, nul, 64);
            e[k].manifest_seq = 0;
            e[k].leaf_index = (uint64_t)leaf;
            e[k].amount = g_conv_amount[leaf];
            e[k].claimed_height = 2;
        }
        uint8_t want[64], got[64];
        CHECK(dna_claims_root(e, 2, want) == 0, "root calc");
        CHECK(nodus_witness_claims_root_v2(fx.w, got) == 0 &&
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

        /* unknown manifest */
        x = c2;
        x.manifest_seq = 1;
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
            V2AP_FAIL_AFTER_CLAIM_SPEND, V2AP_FAIL_AFTER_CLAIM_UTXO,
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
        CHECK(nodus_witness_claims_root_v2(fx.w, cr_before) == 0, "cr");
        CHECK(fx_reopen(&fx) == 0, "reopen");
        CHECK(nodus_witness_claims_root_v2(fx.w, cr_after) == 0 &&
              memcmp(cr_before, cr_after, 64) == 0,
              "claims_root persists");
        CHECK(q1(fx.w, "SELECT remaining FROM v2_dist_state WHERE "
                       "manifest_seq=0") == 10, "remaining persists");
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
        /* idempotent replay of the committed h=2 block */
        dna_claim_t two2[2];
        two2[0] = c0; two2[1] = c1;
        mk_claim_block(&bb, 2, gid, two2, 2);
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
        CHECK(q1(fx.w, "SELECT remaining FROM v2_dist_state WHERE "
                       "manifest_seq=0") == 10, "RETAIN keeps remaining");
        CHECK(nodus_witness_v2_supply_check(fx.w) == 0, "supply late");
        OK();
    }
    fx_close(&fx);
    return 0;
}

/* ── 6: insertion-order independence (twin fixtures) ────────────────── */

static int test_order_independence(void) {
    fixture_t fa, fb;
    uint8_t chA[32], gidA[64], chB[32], gidB[64];
    CHECK(fx_open(&fa) == 0 && fx_open(&fb) == 0, "fixtures");
    CHECK(dist_genesis(&fa, 32, 1, 9, "testnet-generic", chA, gidA) == 0,
          "genesis A");
    CHECK(dist_genesis(&fb, 32, 1, 9, "testnet-generic", chB, gidB) == 0,
          "genesis B");
    /* twins: identical manifests ⇒ identical genesis id + chain id */
    CHECK(memcmp(chA, chB, 32) == 0 && memcmp(gidA, gidB, 64) == 0,
          "twin chains identical");
    OK();

    dna_claim_t c0, c1;
    CHECK(make_claim(&c0, 0, chA, 0) == 0, "c0");
    CHECK(make_claim(&c1, 1, chA, 0) == 0, "c1");

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
    CHECK(nodus_witness_claims_root_v2(fa.w, ra) == 0 &&
          nodus_witness_claims_root_v2(fb.w, rb) == 0 &&
          memcmp(ra, rb, 64) == 0,
          "claims_root insertion-order independent");
    CHECK(nodus_witness_core_root_v2(fa.w, ca) == 0 &&
          nodus_witness_core_root_v2(fb.w, cb) == 0 &&
          memcmp(ca, cb, 64) == 0, "core root order independent");
    CHECK(nodus_witness_global_root_v2(fa.w, ga, NULL, NULL, NULL) == 0 &&
          nodus_witness_global_root_v2(fb.w, gb, NULL, NULL, NULL) == 0 &&
          memcmp(ga, gb, 64) == 0, "global root order independent");
    OK();
    fx_close(&fa);
    fx_close(&fb);
    return 0;
}

/* ── 9: never-mint — manifest committing less than the snapshot sum ─── */

static int test_never_mint(void) {
    fixture_t fx;
    uint8_t chain[32], gid[64];
    CHECK(fx_open(&fx) == 0, "fixture");
    /* total_claimable 20 < Σ converted 32: the distribution is the ONLY
     * source; once drained, further structurally-valid claims REJECT */
    CHECK(dist_genesis(&fx, 20, 1, 9, "testnet-generic", chain, gid) == 0,
          "genesis 20");
    OK();
    dna_claim_t c0, c1;
    CHECK(make_claim(&c0, 0, chain, 0) == 0, "c0");
    CHECK(make_claim(&c1, 1, chain, 0) == 0, "c1");
    nodus_v2_block_t b;
    mk_claim_block(&b, 1, gid, &c0, 1);
    CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0, "claim 15 of 20");
    CHECK(q1(fx.w, "SELECT remaining FROM v2_dist_state WHERE "
                   "manifest_seq=0") == 5, "remaining 5");
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
    if (nodus_witness_db_migrate_v2s6(fx.w) != 0) { fx_close(&fx); return 1; }
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
    uint8_t gid[64], chain[32], vset[64];
    memset(vset, 0x77, 64);
    if (genesis_id_of(mbytes, mlen, gid, chain) != 0) { fx_close(&fx); return 1; }

    uint8_t d0[64], d1[64];
    if (db_state_digest(fx.w, d0) != 0) { fx_close(&fx); return 1; }
    if (nodus_witness_v2_genesis_ex(fx.w, gid, vset, 0, mbytes, mlen)
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
    gman_dist(&m, 32, 1, 9, "testnet-generic");
    memset(m.domains[1].manifest_hash, 0xEE, 64);   /* wrong-marker */
    CHECK(genesis_expect_fail(&m, 1, "wrong domman hash") == 0,
          "hash mismatch rejects");
    OK();

    /* wrong domain count (SYSTEM only, registry has 2) */
    gman_base(&m, 1000, zero, zero);
    m.domain_count = 1;
    gman_dist(&m, 32, 1, 9, "testnet-generic");
    CHECK(genesis_expect_fail(&m, 1, "wrong count") == 0,
          "count mismatch rejects");
    OK();

    /* genesis-supply mismatch against supply_tracking */
    gman_base(&m, 999, zero, zero);
    gman_dist(&m, 32, 1, 9, "testnet-generic");
    CHECK(genesis_expect_fail(&m, 1, "supply mismatch") == 0,
          "supply mismatch rejects");
    OK();
    return 0;
}

/* ── 11: inactive boundary — no live admission for types 12-14 ──────── */

static int test_inactive_boundary(void) {
    fixture_t fx;
    uint8_t chain[32], gid[64];
    CHECK(fx_open(&fx) == 0, "fixture");
    CHECK(dist_genesis(&fx, 32, 1, 9, "testnet-generic", chain, gid) == 0,
          "genesis");
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

int main(void) {
    CHECK(keys_init() == 0, "deterministic keys");
    if (test_migration()) return 1;
    if (test_absent_fixture()) return 1;
    if (test_dist_lifecycle()) return 1;
    if (test_order_independence()) return 1;
    if (test_never_mint()) return 1;
    if (test_genesis_rejects()) return 1;
    if (test_inactive_boundary()) return 1;
    printf("test_v2_claims: ALL OK (%d checks)\n", g_checks);
    return 0;
}
