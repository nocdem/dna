/**
 * Nodus — Ledger V2 S5: versioned schema + atomic migration tests
 * (INACTIVE layer). Real witness chain DBs in temp dirs (heap fixture).
 *
 * §20 "Schema and migration" matrix:
 *   1. fresh DB → migrate → user_version 5, all six v2 tables + the
 *      utxo_set.domain_id column exist;
 *   2. S4-shaped DB (current schema) → migrate;
 *   3. legacy/V1-shaped DB (hand-rolled minimal schema WITHOUT the S4
 *      tables) → migrate;
 *   4. repeated migration is a no-op (idempotent);
 *   5. deterministic failure at EVERY migration stage → full rollback:
 *      user_version still 0, no v2 table, no domain_id column, and a
 *      subsequent migration succeeds;
 *   6. restart after successful migration keeps version + schema;
 *   7. malformed/unknown user_version (7) fails closed, nothing changes;
 *   8. pre-existing UTXOs map to DNA_CORE exactly once (NOT NULL single
 *      column — no duplicate, no missing ownership);
 *   9. no CPUNK table or ownership anywhere.
 *
 * @file test_v2_schema.c
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "nodus/nodus_chain_config.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "dnac/manifest_wire.h"
#include "dnac/vset_wire.h"
#include "dnac/block_v2.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "v2_genesis_fixture.h"   /* v2x_seed_authority / v2x_block_id_at /
                                   * v2x_db_digest — the whole-DB oracle */

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

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
    fx->w = calloc(1, sizeof(*fx->w));   /* multi-MB — ALWAYS heap */
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_schema_XXXXXX");
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain_id16, 0x22, sizeof(fx->chain_id16));
    if (nodus_witness_create_chain_db(fx->w, fx->chain_id16) != 0) {
        rmrf(fx->dir); free(fx->w); fx->w = NULL;
        return -1;
    }
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

static int count_q(sqlite3 *db, const char *sql, int *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int rc = sqlite3_step(st);
    if (rc != SQLITE_ROW) { sqlite3_finalize(st); return -1; }
    *out = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return 0;
}

static int has_table(sqlite3 *db, const char *name) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_ROW ? 1 : 0;
}

static int has_domain_col(sqlite3 *db) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "PRAGMA table_info(utxo_set)", -1, &st,
                           NULL) != SQLITE_OK)
        return -1;
    int found = 0, rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(st, 1);
        if (name && strcmp((const char *)name, "domain_id") == 0) found = 1;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? found : -1;
}

static const char *V2_TABLES[6] = {
    "v2_blocks", "v2_domain_heads", "v2_domain_updates",
    "v2_root_history", "v2_tx_index", "v2_tx_local_index"
};

static int schema_absent(sqlite3 *db) {
    for (int i = 0; i < 6; i++)
        if (has_table(db, V2_TABLES[i]) != 0) return 0;
    if (has_domain_col(db) != 0) return 0;
    return 1;
}

static int schema_present(sqlite3 *db) {
    for (int i = 0; i < 6; i++)
        if (has_table(db, V2_TABLES[i]) != 1) return 0;
    if (has_domain_col(db) != 1) return 0;
    return 1;
}

/* ════════════════════════════════════════════════════════════════════════
 * S12 apply-side fixture: a present-distribution successor genesis at S12,
 * then a claim block through the REAL apply engine — proving phase 12c
 * persists v2_claim_counts (every block) + v2_claim_bytes (byte-equal to
 * the submitted canonical claim), and that F49 rolls both back with the
 * whole-DB digest unchanged. Distribution/claim shape mirrors
 * test_v2_claims.c (the T4 dispatch's "reuse the claim fixtures").
 * ════════════════════════════════════════════════════════════════════ */

#define S12_N_LEAVES 3
static uint8_t s12_pk[S12_N_LEAVES][QGP_DSA87_PUBLICKEYBYTES];
static uint8_t s12_sk[S12_N_LEAVES][QGP_DSA87_SECRETKEYBYTES];
static dna_dist_leaf_t s12_leaf[S12_N_LEAVES];
static uint8_t s12_leaf_hash[S12_N_LEAVES][64];
static uint8_t s12_snapshot_root[64];

/* conv 3/2 FLOOR: 10->15, 5->7, 7->10; sum = 32 */
static const uint64_t s12_src_amount[S12_N_LEAVES] = { 10, 5, 7 };
static const char *s12_src_id[S12_N_LEAVES] =
    { "src-alpha", "src-beta", "src-gamma" };
static const uint8_t s12_native_asset[64] = {0};   /* CORE native token   */

static uint64_t s12_q1(nodus_witness_t *w, const char *sql) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return UINT64_MAX;
    uint64_t v = UINT64_MAX;
    if (sqlite3_step(st) == SQLITE_ROW)
        v = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

static int s12_keys_init(void) {
    for (int i = 0; i < S12_N_LEAVES; i++) {
        uint8_t seed[32];
        memset(seed, (uint8_t)(0x90 + i), sizeof(seed));
        if (qgp_dsa87_keypair_derand(s12_pk[i], s12_sk[i], seed) != 0)
            return -1;
        memset(&s12_leaf[i], 0, sizeof(s12_leaf[i]));
        s12_leaf[i].leaf_version = DNA_DIST_VERSION;
        s12_leaf[i].source_id_len = (uint16_t)strlen(s12_src_id[i]);
        memcpy(s12_leaf[i].source_id, s12_src_id[i], s12_leaf[i].source_id_len);
        s12_leaf[i].source_amount = s12_src_amount[i];
        if (qgp_sha3_512(s12_pk[i], QGP_DSA87_PUBLICKEYBYTES,
                         s12_leaf[i].dest_binding) != 0)
            return -1;
        if (dna_dist_leaf_hash(&s12_leaf[i], s12_leaf_hash[i]) != 0)
            return -1;
    }
    if (dna_dist_snapshot_root(s12_leaf, S12_N_LEAVES, s12_snapshot_root) != 0)
        return -1;
    return dna_dist_check_totals(s12_leaf, S12_N_LEAVES, 3, 2,
                                 DNA_DISTROUND_FLOOR, 32);
}

/* genesis(1000) = CORE utxo(1000-total) + unclaimed distribution(total). */
static int s12_seed_supply(nodus_witness_t *w, uint64_t utxo_amount) {
    char sql[640];
    if (run_sql(w->db,
            "INSERT INTO supply_tracking (id, genesis_supply, total_burned, "
            "total_minted, current_supply, last_tx_hash, last_sequence) "
            "VALUES (1, 1000, 0, 0, 1000, x'00', 0)") != 0)
        return -1;
    snprintf(sql, sizeof(sql),
        "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
        "tx_hash, output_index, block_height, created_at, unlock_block, "
        "domain_id) "
        "VALUES (zeroblob(63)||x'01', 'genesis', %llu, zeroblob(64), "
        "zeroblob(63)||x'aa', 0, 0, 0, 0, 1)",
        (unsigned long long)utxo_amount);
    return run_sql(w->db, sql);
}

/* present-distribution GenesisManifest over the committed SYSTEM/CORE
 * registry hashes (CORE-native target, 3-leaf snapshot). */
static int s12_build_dist_manifest(nodus_witness_t *w, uint8_t *out,
                                   size_t cap, size_t *out_len,
                                   uint8_t out_mh[64]) {
    dna_domain_manifest_t dm;
    uint8_t sys_h[64], core_h[64];
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_SYSTEM, NULL, &dm, NULL) != 0)
        return -1;
    if (dna_domman_hash(&dm, sys_h) != 0) return -1;
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_CORE, NULL, &dm, NULL) != 0)
        return -1;
    if (dna_domman_hash(&dm, core_h) != 0) return -1;

    dna_gman_t m;
    memset(&m, 0, sizeof(m));
    m.manifest_version   = DNA_GMAN_VERSION;
    m.genesis_supply_raw = 1000;
    m.domain_count       = 2;
    m.domains[0].domain_id = DNA_DOMAIN_SYSTEM;
    memcpy(m.domains[0].manifest_hash, sys_h, 64);
    m.domains[1].domain_id = DNA_DOMAIN_CORE;
    memcpy(m.domains[1].manifest_hash, core_h, 64);
    m.dist_present       = 1;
    m.dist_version       = DNA_DIST_VERSION;
    m.target_domain_id   = DNA_DOMAIN_CORE;
    m.target_asset_len   = 64;
    memcpy(m.target_asset_ref, s12_native_asset, 64);
    m.source_tag_len     = (uint16_t)strlen("testnet-generic");
    memcpy(m.source_tag, "testnet-generic", m.source_tag_len);
    m.source_commit_len  = 16;
    memset(m.source_commit, 0x77, 16);
    memcpy(m.snapshot_root, s12_snapshot_root, 64);
    m.leaf_count         = S12_N_LEAVES;
    m.conv_numerator     = 3;
    m.conv_denominator   = 2;
    m.rounding_mode      = DNA_DISTROUND_FLOOR;
    m.excluded_amount    = 4;
    m.total_claimable    = 32;
    m.claim_start_height = 1;
    m.claim_end_height   = 1000000;
    m.auth_mode          = DNA_CLAIMAUTH_DNA_NATIVE;
    m.fee_mode           = DNA_CLAIMFEE_NONE;
    m.post_deadline_mode = DNA_POSTDL_RETAIN;

    if (dna_gman_hash(&m, out_mh) != 0) return -1;
    return dna_gman_encode(&m, out, cap, out_len);
}

/* fresh fixture → S12 → present-distribution genesis. Reports the derived
 * chain id + genesis BlockID + the committed manifest hash. */
static int s12_open_dist(fixture_t *fx, uint8_t out_chain[32],
                         uint8_t out_gid[64], uint8_t out_mh[64]) {
    if (fx_open(fx) != 0) return -1;
    if (nodus_chain_config_db_migrate(fx->w) != 0) return -1;
    if (nodus_witness_db_migrate_v2s12(fx->w) != 0) return -1;
    /* supply + CORE utxo BEFORE the registry commits genesis roots */
    if (s12_seed_supply(fx->w, 1000 - 32) != 0) return -1;
    /* committed validator authority BEFORE domreg genesis (the vset leg
     * feeds the SYSTEM payload root genesis re-derives). */
    if (v2x_seed_authority(fx->w) != 0) return -1;
    if (nodus_witness_domreg_init_genesis(fx->w) != 0) return -1;

    uint8_t mbytes[8192];
    size_t mlen = 0;
    if (s12_build_dist_manifest(fx->w, mbytes, sizeof(mbytes), &mlen,
                                out_mh) != 0)
        return -1;

    uint8_t vsh[DNA_VSET_HASH_LEN];
    memset(vsh, 0x77, sizeof(vsh));
    {
        dna_vset_snapshot_t *s0 = NULL;
        uint32_t sn = 0, sq = 0;
        if (nodus_witness_v2_epoch_authority_for_height(fx->w, 0, &s0, &sn,
                                                        &sq) != 0 || !s0) {
            dna_vset_free(&s0);
            return -1;
        }
        int hrc = dna_vset_hash(s0, vsh);
        dna_vset_free(&s0);
        if (hrc != 0) return -1;
    }
    if (nodus_witness_v2_genesis_ex(fx->w, NULL, vsh, 0, mbytes, mlen) != 0)
        return -1;

    uint8_t gid[64];
    if (v2x_block_id_at(fx->w, 0, gid) != 0) return -1;
    if (out_gid)   memcpy(out_gid, gid, 64);
    if (out_chain) memcpy(out_chain, gid, 32);
    return 0;
}

static int s12_make_claim(dna_claim_t *c, int leaf, const uint8_t chain[32],
                          const uint8_t manifest_hash[64]) {
    memset(c, 0, sizeof(*c));
    c->claim_version = DNA_CLAIM_VERSION;
    memcpy(c->chain_id, chain, 32);
    memcpy(c->manifest_hash, manifest_hash, 64);
    c->leaf_index = (uint64_t)leaf;
    c->source_id_len = s12_leaf[leaf].source_id_len;
    memcpy(c->source_id, s12_leaf[leaf].source_id, c->source_id_len);
    c->source_amount = s12_leaf[leaf].source_amount;
    memcpy(c->dest_binding, s12_leaf[leaf].dest_binding, 64);
    uint16_t ns = 0;
    if (dna_dist_proof_build((const uint8_t (*)[64])s12_leaf_hash,
                             S12_N_LEAVES, (uint64_t)leaf, c->siblings,
                             &ns) != 0)
        return -1;
    c->n_siblings = ns;
    c->auth_mode = DNA_CLAIMAUTH_DNA_NATIVE;
    memcpy(c->pubkey, s12_pk[leaf], QGP_DSA87_PUBLICKEYBYTES);
    uint8_t pre[DNA_CLAIM_PREIMAGE_MAX];
    size_t pre_len = 0;
    if (dna_claim_preimage(c, pre, &pre_len) != 0) return -1;
    size_t siglen = 0;
    if (qgp_dsa87_sign(c->signature, &siglen, pre, pre_len,
                       s12_sk[leaf]) != 0 || siglen != DNA_CLAIM_SIG_LEN)
        return -1;
    return 0;
}

/* canonical wire bytes + SHA3-512 of a claim (the phase-12c persistence
 * contract, computed independently here). */
static int s12_encode_claim(const dna_claim_t *c, uint8_t **out,
                            size_t *out_len, uint8_t hash[64]) {
    size_t need = dna_claim_encoded_len(c);
    if (need == 0) return -1;
    uint8_t *b = malloc(need);
    if (!b) return -1;
    size_t wr = 0;
    if (dna_claim_encode(c, b, need, &wr) != 0 || wr != need) {
        free(b); return -1;
    }
    if (qgp_sha3_512(b, wr, hash) != 0) { free(b); return -1; }
    *out = b; *out_len = wr;
    return 0;
}

static void s12_mk_block(nodus_v2_block_t *b, uint64_t h,
                         const dna_claim_t *claims, size_t n_claims) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = 0;                        /* h < DNAC_EPOCH_LENGTH          */
    b->claims = claims;
    b->n_claims = n_claims;
}

/* the persisted claim-bytes row at (h, idx) equals `bytes`/`hash`. */
static int s12_claim_row_equals(nodus_witness_t *w, uint64_t h, uint64_t idx,
                                const uint8_t *bytes, size_t len,
                                const uint8_t hash[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT claim_hash, claim FROM v2_claim_bytes "
            "WHERE global_height=?1 AND claim_index=?2", -1, &st, NULL)
        != SQLITE_OK)
        return 0;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)h);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)idx);
    int ok = 0;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const void *hb = sqlite3_column_blob(st, 0);
        int hl = sqlite3_column_bytes(st, 0);
        const void *cb = sqlite3_column_blob(st, 1);
        int cl = sqlite3_column_bytes(st, 1);
        ok = (hl == 64 && hb && memcmp(hb, hash, 64) == 0 &&
              cl == (int)len && cb && memcmp(cb, bytes, len) == 0);
    }
    sqlite3_finalize(st);
    return ok;
}

static int run_s12_apply_matrix(void) {
    CHECK(s12_keys_init() == 0, "s12 distribution leaves"); OK();

    /* ── A. claim-bearing block: counts[h]==n, bytes byte-equal ──────── */
    {
        fixture_t fx;
        uint8_t chain[32], gid[64], mh[64];
        CHECK(s12_open_dist(&fx, chain, gid, mh) == 0,
              "S12 present-distribution genesis"); OK();
        uint32_t sv = 0;
        CHECK(nodus_witness_db_schema_version(fx.w, &sv) == 0 && sv == 12,
              "fixture DB at S12"); OK();
        CHECK(has_table(fx.w->db, "v2_claim_bytes") == 1 &&
              has_table(fx.w->db, "v2_claim_counts") == 1,
              "S12 claim tables present"); OK();

        /* genesis (h=0) is committed by nodus_witness_v2_genesis_ex, NOT
         * the apply-block phase-12c path — so it carries NO count row,
         * exactly as it carries no v2_tx_bytes rows. Genesis is served to
         * a joiner via the Faz D bundle, never the claim-count seam. */
        CHECK(s12_q1(fx.w, "SELECT COUNT(*) FROM v2_claim_counts "
                           "WHERE global_height=0") == 0,
              "genesis carries no count row (bundle-served)"); OK();

        dna_claim_t c0, c1;
        CHECK(s12_make_claim(&c0, 0, chain, mh) == 0, "claim0");
        CHECK(s12_make_claim(&c1, 1, chain, mh) == 0, "claim1"); OK();
        uint8_t *c0b = NULL, *c1b = NULL; size_t c0n = 0, c1n = 0;
        uint8_t c0h[64], c1h[64];
        CHECK(s12_encode_claim(&c0, &c0b, &c0n, c0h) == 0, "encode c0");
        CHECK(s12_encode_claim(&c1, &c1b, &c1n, c1h) == 0, "encode c1"); OK();

        dna_claim_t claims[2] = { c0, c1 };
        nodus_v2_block_t b;
        s12_mk_block(&b, 1, claims, 2);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b) == 0,
              "claim block h=1 commits"); OK();

        CHECK(s12_q1(fx.w, "SELECT n_claims FROM v2_claim_counts "
                           "WHERE global_height=1") == 2,
              "count row h=1 = 2"); OK();
        CHECK(s12_q1(fx.w, "SELECT COUNT(*) FROM v2_claim_bytes "
                           "WHERE global_height=1") == 2,
              "two claim-bytes rows at h=1"); OK();
        CHECK(s12_claim_row_equals(fx.w, 1, 0, c0b, c0n, c0h),
              "claim_index 0 byte-equal + hashed"); OK();
        CHECK(s12_claim_row_equals(fx.w, 1, 1, c1b, c1n, c1h),
              "claim_index 1 byte-equal + hashed"); OK();
        /* the claims actually APPLIED (two nullifiers spent) — the block
         * really committed, not a vacuous count row. */
        CHECK(s12_q1(fx.w, "SELECT COUNT(*) FROM v2_claims_spent") == 2,
              "both claims applied (spent set)"); OK();

        /* ── B. claim-free block: count row 0, no bytes rows ─────────── */
        nodus_v2_block_t b2;
        s12_mk_block(&b2, 2, NULL, 0);
        CHECK(nodus_witness_v2_apply_block(fx.w, &b2) == 0,
              "claim-free block h=2 commits"); OK();
        CHECK(s12_q1(fx.w, "SELECT n_claims FROM v2_claim_counts "
                           "WHERE global_height=2") == 0,
              "count row h=2 = 0"); OK();
        CHECK(s12_q1(fx.w, "SELECT COUNT(*) FROM v2_claim_bytes "
                           "WHERE global_height=2") == 0,
              "no claim-bytes rows for a claim-free block"); OK();

        free(c0b); free(c1b);
        fx_close(&fx);
    }

    /* ── C. F49 fault → whole-DB digest-identical rollback + clean retry ─ */
    {
        fixture_t fx;
        uint8_t chain[32], gid[64], mh[64];
        CHECK(s12_open_dist(&fx, chain, gid, mh) == 0,
              "S12 fixture for F49"); OK();

        dna_claim_t c0, c1;
        CHECK(s12_make_claim(&c0, 0, chain, mh) == 0, "F49 claim0");
        CHECK(s12_make_claim(&c1, 1, chain, mh) == 0, "F49 claim1"); OK();

        uint8_t d_before[64];
        CHECK(v2x_db_digest(fx.w, d_before) == 0, "digest before F49"); OK();

        dna_claim_t claims[2] = { c0, c1 };
        nodus_v2_block_t bf;
        s12_mk_block(&bf, 1, claims, 2);
        bf.fail_at = V2AP_FAIL_AFTER_CLAIM_BYTES;
        CHECK(nodus_witness_v2_apply_block(fx.w, &bf) == -1,
              "F49 rejects (verdict)"); OK();

        uint8_t d_after[64];
        CHECK(v2x_db_digest(fx.w, d_after) == 0, "digest after F49"); OK();
        CHECK(memcmp(d_before, d_after, 64) == 0,
              "F49 rolled back byte-identically"); OK();
        CHECK(s12_q1(fx.w, "SELECT COUNT(*) FROM v2_claim_counts "
                           "WHERE global_height=1") == 0,
              "no count row survived the fault"); OK();
        CHECK(s12_q1(fx.w, "SELECT COUNT(*) FROM v2_claim_bytes "
                           "WHERE global_height=1") == 0,
              "no claim-bytes row survived the fault"); OK();

        /* clean retry commits — the rolled-back nullifiers were never
         * spent, so the identical block now applies. */
        dna_claim_t claims2[2] = { c0, c1 };
        nodus_v2_block_t bok;
        s12_mk_block(&bok, 1, claims2, 2);
        CHECK(nodus_witness_v2_apply_block(fx.w, &bok) == 0,
              "clean retry commits"); OK();
        CHECK(s12_q1(fx.w, "SELECT n_claims FROM v2_claim_counts "
                           "WHERE global_height=1") == 2,
              "retry persisted the count row"); OK();
        CHECK(s12_q1(fx.w, "SELECT COUNT(*) FROM v2_claim_bytes "
                           "WHERE global_height=1") == 2,
              "retry persisted the claim bytes"); OK();

        fx_close(&fx);
    }
    return 0;
}

int main(void) {
    /* ── 1+2. fresh / S4-shaped DB (current production schema) ──────── */
    fixture_t fx;
    CHECK(fx_open(&fx) == 0, "fixture open"); OK();

    uint32_t ver = 99;
    CHECK(nodus_witness_db_schema_version(fx.w, &ver) == 0 && ver == 0,
          "fresh DB version != 0"); OK();
    CHECK(schema_absent(fx.w->db), "v2 schema pre-exists"); OK();

    /* pre-existing "legacy" UTXOs (inserted BEFORE the migration, with
     * the production column list — no domain column) */
    CHECK(run_sql(fx.w->db,
        "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
        " tx_hash, output_index, block_height, created_at, unlock_block) "
        "VALUES (x'01', 'fpA', 100, x'00', x'aa', 0, 1, 0, 0),"
        "       (x'02', 'fpB', 250, x'00', x'bb', 0, 1, 0, 0)") == 0,
        "seed utxos"); OK();

    /* ── 5. failure at EVERY stage → full rollback, then success ────── */
    for (int stage = V2MIG_FAIL_AFTER_BEGIN;
         stage <= V2MIG_FAIL_BEFORE_COMMIT; stage++) {
        CHECK(nodus_witness_db_migrate_v2s5_ex(fx.w,
                  (nodus_v2_mig_fail_t)stage) == -1,
              "staged failure did not fail");
        CHECK(nodus_witness_db_schema_version(fx.w, &ver) == 0 && ver == 0,
              "failed migration left a version");
        CHECK(schema_absent(fx.w->db),
              "failed migration left schema fragments");
    }
    OK();

    /* the DB is still fully usable and migrates cleanly afterwards */
    CHECK(nodus_witness_db_migrate_v2s5(fx.w) == 0, "migrate"); OK();
    CHECK(nodus_witness_db_schema_version(fx.w, &ver) == 0 && ver == 5,
          "version != 5"); OK();
    CHECK(schema_present(fx.w->db), "schema incomplete"); OK();

    /* ── 4. idempotent re-run ───────────────────────────────────────── */
    CHECK(nodus_witness_db_migrate_v2s5(fx.w) == 0, "re-migrate"); OK();
    CHECK(nodus_witness_db_schema_version(fx.w, &ver) == 0 && ver == 5,
          "re-migrate changed version"); OK();

    /* ── 8. every pre-existing UTXO owned by DNA_CORE exactly once ──── */
    int n = -1;
    CHECK(count_q(fx.w->db, "SELECT COUNT(*) FROM utxo_set", &n) == 0 &&
          n == 2, "utxo count"); OK();
    CHECK(count_q(fx.w->db,
          "SELECT COUNT(*) FROM utxo_set WHERE domain_id = 1", &n) == 0 &&
          n == 2, "legacy UTXOs not DNA_CORE-owned"); OK();
    CHECK(count_q(fx.w->db,
          "SELECT COUNT(*) FROM utxo_set WHERE domain_id IS NULL", &n) == 0
          && n == 0, "nullable ownership"); OK();
    /* NO permanent domain default exists: an insert that does not name
     * its owning domain FAILS (NOT NULL, no default) — ownership is
     * always explicit on the generic path. */
    {
        char *err = NULL;
        CHECK(sqlite3_exec(fx.w->db,
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
            " tx_hash, output_index, block_height, created_at, "
            "unlock_block) "
            "VALUES (x'03', 'fpC', 7, x'00', x'cc', 0, 2, 0, 0)",
            NULL, NULL, &err) != SQLITE_OK,
            "ownerless insert must fail");
        sqlite3_free(err);
        OK();
    }
    /* the schema itself carries no default for domain_id */
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
              "SELECT dflt_value FROM pragma_table_info('utxo_set') "
              "WHERE name='domain_id'", -1, &st, NULL) == SQLITE_OK &&
              sqlite3_step(st) == SQLITE_ROW &&
              sqlite3_column_type(st, 0) == SQLITE_NULL,
              "domain_id must have NO schema default");
        sqlite3_finalize(st);
        OK();
    }
    /* an EXPLICITLY-owned insert works */
    CHECK(run_sql(fx.w->db,
        "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
        " tx_hash, output_index, block_height, created_at, unlock_block, "
        "domain_id) "
        "VALUES (x'03', 'fpC', 7, x'00', x'cc', 0, 2, 0, 0, 1)") == 0,
        "explicit-owner insert");
    CHECK(count_q(fx.w->db,
          "SELECT domain_id FROM utxo_set WHERE nullifier = x'03'", &n) == 0
          && n == 1, "explicit UTXO ownership"); OK();

    /* ── 6. restart keeps version + schema + ownership ──────────────── */
    CHECK(fx_reopen(&fx) == 0, "reopen");
    CHECK(nodus_witness_db_schema_version(fx.w, &ver) == 0 && ver == 5,
          "restart lost version"); OK();
    CHECK(schema_present(fx.w->db), "restart lost schema"); OK();
    CHECK(count_q(fx.w->db,
          "SELECT COUNT(*) FROM utxo_set WHERE domain_id = 1", &n) == 0 &&
          n == 3, "restart lost ownership"); OK();

    /* ── 9. no CPUNK table or ownership anywhere ────────────────────── */
    CHECK(count_q(fx.w->db,
          "SELECT COUNT(*) FROM sqlite_master "
          "WHERE LOWER(name) LIKE '%cpunk%'", &n) == 0 && n == 0,
          "CPUNK table exists"); OK();
    CHECK(count_q(fx.w->db,
          "SELECT COUNT(*) FROM utxo_set WHERE domain_id NOT IN (0, 1)",
          &n) == 0 && n == 0, "foreign domain ownership"); OK();
    fx_close(&fx);

    /* ── 7. malformed/unknown version fails closed ──────────────────── */
    fixture_t fx2;
    CHECK(fx_open(&fx2) == 0, "fixture 2");
    CHECK(run_sql(fx2.w->db, "PRAGMA user_version = 7") == 0, "set 7");
    CHECK(nodus_witness_db_migrate_v2s5(fx2.w) == -1,
          "unknown version migrated"); OK();
    CHECK(nodus_witness_db_schema_version(fx2.w, &ver) == 0 && ver == 7,
          "unknown version mutated"); OK();
    CHECK(schema_absent(fx2.w->db), "unknown version got schema"); OK();
    fx_close(&fx2);

    /* ── 3. legacy/V1-shaped DB: minimal hand-rolled schema WITHOUT any
     * S4 table — the migration must still succeed (it touches only
     * utxo_set + new tables) ───────────────────────────────────────── */
    {
        nodus_witness_t *w = calloc(1, sizeof(*w));
        CHECK(w != NULL, "alloc");
        CHECK(sqlite3_open(":memory:", &w->db) == SQLITE_OK, "mem db");
        CHECK(run_sql(w->db,
            "CREATE TABLE utxo_set ("
            "  nullifier BLOB PRIMARY KEY, owner TEXT NOT NULL,"
            "  amount INTEGER NOT NULL, token_id BLOB NOT NULL,"
            "  tx_hash BLOB NOT NULL, output_index INTEGER NOT NULL,"
            "  block_height INTEGER NOT NULL DEFAULT 0,"
            "  created_at INTEGER NOT NULL DEFAULT 0,"
            "  unlock_block INTEGER NOT NULL DEFAULT 0);"
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id,"
            " tx_hash, output_index) VALUES (x'aa', 'legacy', 42, x'00',"
            " x'11', 0)") == 0, "legacy schema"); OK();
        CHECK(nodus_witness_db_migrate_v2s5(w) == 0, "legacy migrate");
        OK();
        uint32_t v2 = 0;
        CHECK(nodus_witness_db_schema_version(w, &v2) == 0 && v2 == 5,
              "legacy version"); OK();
        int m = -1;
        CHECK(count_q(w->db,
              "SELECT domain_id FROM utxo_set WHERE nullifier = x'aa'",
              &m) == 0 && m == 1, "legacy UTXO ownership"); OK();
        sqlite3_close(w->db);
        free(w);
    }

    /* ══ INTENT SEASON: the S8 migration matrix (7 → 8) ═════════════ */
    {
        fixture_t f8;
        CHECK(fx_open(&f8) == 0, "fixture 8");

        /* 0 → 8 full chain on a fresh DB */
        CHECK(nodus_witness_db_migrate_v2s8(f8.w) == 0, "0→8"); OK();
        CHECK(nodus_witness_db_schema_version(f8.w, &ver) == 0 &&
              ver == 8, "version != 8"); OK();
        CHECK(has_table(f8.w->db, "v2_intent_index") == 1,
              "v2_intent_index missing"); OK();

        /* idempotent re-run */
        CHECK(nodus_witness_db_migrate_v2s8(f8.w) == 0, "re-run 8"); OK();
        CHECK(nodus_witness_db_schema_version(f8.w, &ver) == 0 &&
              ver == 8, "re-run changed version"); OK();

        /* EARLIER seasons' migrations refuse a v8 DB (no forward
         * reinterpretation) */
        CHECK(nodus_witness_db_migrate_v2s5(f8.w) == -1, "s5 at 8"); OK();
        CHECK(nodus_witness_db_migrate_v2s6(f8.w) == -1, "s6 at 8"); OK();
        CHECK(nodus_witness_db_migrate_v2s7(f8.w) == -1, "s7 at 8"); OK();

        /* UNIQUENESS BACKSTOP: intent_id PK and tx_id UNIQUE both hold */
        CHECK(run_sql(f8.w->db,
              "INSERT INTO v2_intent_index (intent_id, tx_id, "
              "global_height, global_index) "
              "VALUES (x'01', x'aa', 1, 0)") == 0, "seed intent row"); OK();
        {
            char *err = NULL;
            CHECK(sqlite3_exec(f8.w->db,
                  "INSERT INTO v2_intent_index (intent_id, tx_id, "
                  "global_height, global_index) "
                  "VALUES (x'01', x'bb', 2, 0)", NULL, NULL, &err)
                  != SQLITE_OK, "duplicate intent_id accepted");
            sqlite3_free(err);
            err = NULL;
            CHECK(sqlite3_exec(f8.w->db,
                  "INSERT INTO v2_intent_index (intent_id, tx_id, "
                  "global_height, global_index) "
                  "VALUES (x'02', x'aa', 2, 0)", NULL, NULL, &err)
                  != SQLITE_OK, "duplicate wire realization accepted");
            sqlite3_free(err);
            OK();
        }
        fx_close(&f8);
    }
    {
        /* CONSTRAINT VERIFICATION (review-round fix): a pre-existing
         * v2_intent_index whose column NAMES match but which lacks the
         * PK/UNIQUE constraints must REFUSE to migrate — those
         * constraints are the replay backstop, and CREATE TABLE IF NOT
         * EXISTS would otherwise adopt the naked table silently. */
        fixture_t fc;
        CHECK(fx_open(&fc) == 0, "fixture c");
        CHECK(nodus_witness_db_migrate_v2s7(fc.w) == 0, "0→7 c"); OK();
        CHECK(run_sql(fc.w->db,
              "CREATE TABLE v2_intent_index ("
              "  intent_id BLOB NOT NULL,"
              "  tx_id BLOB NOT NULL,"
              "  global_height INTEGER NOT NULL,"
              "  global_index INTEGER NOT NULL)") == 0,
              "plant naked table"); OK();
        CHECK(nodus_witness_db_migrate_v2s8(fc.w) == -1,
              "constraint-free intent table migrated"); OK();
        CHECK(nodus_witness_db_schema_version(fc.w, &ver) == 0 &&
              ver == 7, "refusal moved version"); OK();
        CHECK(run_sql(fc.w->db, "DROP TABLE v2_intent_index") == 0,
              "drop naked table"); OK();
        CHECK(nodus_witness_db_migrate_v2s8(fc.w) == 0,
              "7→8 after drop"); OK();
        fx_close(&fc);
    }
    {
        /* staged fault injection inside 7 → 8: every stage rolls back to
         * a VALID version-7 schema; the migration then succeeds. */
        fixture_t f9;
        CHECK(fx_open(&f9) == 0, "fixture 9");
        CHECK(nodus_witness_db_migrate_v2s7(f9.w) == 0, "0→7"); OK();
        for (int stage = V2S8MIG_FAIL_AFTER_BEGIN;
             stage <= V2S8MIG_FAIL_BEFORE_COMMIT; stage++) {
            CHECK(nodus_witness_db_migrate_v2s8_ex(f9.w,
                      (nodus_v2s8_mig_fail_t)stage) == -1,
                  "staged S8 failure did not fail");
            CHECK(nodus_witness_db_schema_version(f9.w, &ver) == 0 &&
                  ver == 7, "failed S8 stage moved the version");
            CHECK(has_table(f9.w->db, "v2_intent_index") == 0,
                  "failed S8 stage left the intent table");
        }
        OK();

        /* POPULATED-WIRE-INDEX REFUSAL: committed pre-S8 transactions
         * cannot be backfilled with intent identities — fail closed. */
        CHECK(run_sql(f9.w->db,
              "INSERT INTO v2_tx_index (global_height, global_index, "
              "tx_id, owner_domain, touched, wire_version) "
              "VALUES (1, 0, x'aa', 0, x'000100000001', 3)") == 0,
              "seed wire row"); OK();
        CHECK(nodus_witness_db_migrate_v2s8(f9.w) == -1,
              "populated wire index migrated"); OK();
        CHECK(nodus_witness_db_schema_version(f9.w, &ver) == 0 &&
              ver == 7, "refusal moved the version"); OK();
        CHECK(has_table(f9.w->db, "v2_intent_index") == 0,
              "refusal left the intent table"); OK();
        CHECK(run_sql(f9.w->db, "DELETE FROM v2_tx_index") == 0,
              "clear wire index"); OK();
        CHECK(nodus_witness_db_migrate_v2s8(f9.w) == 0,
              "7→8 after clear"); OK();
        CHECK(nodus_witness_db_schema_version(f9.w, &ver) == 0 &&
              ver == 8, "post-clear version"); OK();

        /* restart keeps version + table */
        CHECK(fx_reopen(&f9) == 0, "reopen 9");
        CHECK(nodus_witness_db_schema_version(f9.w, &ver) == 0 &&
              ver == 8, "restart lost v8"); OK();
        CHECK(has_table(f9.w->db, "v2_intent_index") == 1,
              "restart lost intent table"); OK();
        fx_close(&f9);
    }
    {
        /* unknown/newer version (9) fails closed for S8 too */
        fixture_t fa;
        CHECK(fx_open(&fa) == 0, "fixture a");
        CHECK(run_sql(fa.w->db, "PRAGMA user_version = 9") == 0, "set 9");
        CHECK(nodus_witness_db_migrate_v2s8(fa.w) == -1,
              "version 9 migrated"); OK();
        CHECK(nodus_witness_db_schema_version(fa.w, &ver) == 0 &&
              ver == 9, "version 9 mutated"); OK();
        fx_close(&fa);
    }

    /* ════════════════════════════════════════════════════════════════
     * S12 (O15F Task 4) — per-block claim-byte schema migration matrix.
     * ════════════════════════════════════════════════════════════════ */

    /* S12-fresh: 0 → 12 in one call, both tables with the exact shape. */
    {
        fixture_t f12;
        CHECK(fx_open(&f12) == 0, "fixture s12 fresh");
        CHECK(nodus_witness_db_migrate_v2s12(f12.w) == 0, "0->12"); OK();
        CHECK(nodus_witness_db_schema_version(f12.w, &ver) == 0 && ver == 12,
              "version != 12"); OK();
        CHECK(has_table(f12.w->db, "v2_claim_bytes") == 1 &&
              has_table(f12.w->db, "v2_claim_counts") == 1,
              "S12 tables missing"); OK();
        /* the earlier schemas remain present (additive superset) */
        CHECK(has_table(f12.w->db, "v2_tx_bytes") == 1 &&
              has_table(f12.w->db, "v2_blocks") == 1,
              "S12 dropped an earlier table"); OK();
        /* idempotent re-run */
        CHECK(nodus_witness_db_migrate_v2s12(f12.w) == 0, "re-run 12"); OK();
        CHECK(nodus_witness_db_schema_version(f12.w, &ver) == 0 && ver == 12,
              "re-run moved version"); OK();
        /* restart keeps it */
        CHECK(fx_reopen(&f12) == 0, "reopen s12");
        CHECK(nodus_witness_db_schema_version(f12.w, &ver) == 0 && ver == 12,
              "restart lost v12"); OK();
        CHECK(has_table(f12.w->db, "v2_claim_counts") == 1,
              "restart lost claim table"); OK();
        fx_close(&f12);
    }

    /* S12-upgrade + fault stages: from a valid S11 base, EVERY stage rolls
     * back to a byte-identical version-11 database (whole-DB digest oracle
     * + explicit version/table checks — user_version is a pragma, outside
     * the digest, so both are asserted), then the migration succeeds. */
    {
        fixture_t f11;
        CHECK(fx_open(&f11) == 0, "fixture s11 base");
        CHECK(nodus_witness_db_migrate_v2s11(f11.w) == 0, "0->11"); OK();
        CHECK(nodus_witness_db_schema_version(f11.w, &ver) == 0 && ver == 11,
              "base not at 11"); OK();

        uint8_t d11[64];
        CHECK(v2x_db_digest(f11.w, d11) == 0, "S11 base digest"); OK();

        for (int stage = V2S12MIG_FAIL_AFTER_BEGIN;
             stage <= V2S12MIG_FAIL_BEFORE_COMMIT; stage++) {
            CHECK(nodus_witness_db_migrate_v2s12_ex(f11.w,
                      (nodus_v2s12_mig_fail_t)stage) == -1,
                  "staged S12 failure did not fail");
            CHECK(nodus_witness_db_schema_version(f11.w, &ver) == 0 &&
                  ver == 11, "failed S12 stage moved the version");
            CHECK(has_table(f11.w->db, "v2_claim_bytes") == 0 &&
                  has_table(f11.w->db, "v2_claim_counts") == 0,
                  "failed S12 stage left a claim table");
            uint8_t dnow[64];
            CHECK(v2x_db_digest(f11.w, dnow) == 0, "post-stage digest");
            CHECK(memcmp(d11, dnow, 64) == 0,
                  "failed S12 stage mutated the DB");
        }
        OK();

        CHECK(nodus_witness_db_migrate_v2s12(f11.w) == 0, "11->12"); OK();
        CHECK(nodus_witness_db_schema_version(f11.w, &ver) == 0 && ver == 12,
              "post-fault version != 12"); OK();
        CHECK(has_table(f11.w->db, "v2_claim_counts") == 1,
              "post-fault claim table missing"); OK();
        fx_close(&f11);
    }

    /* S12 unknown/newer version (13) fails closed — nothing changes. */
    {
        fixture_t f13;
        CHECK(fx_open(&f13) == 0, "fixture s12 v13");
        CHECK(run_sql(f13.w->db, "PRAGMA user_version = 13") == 0, "set 13");
        CHECK(nodus_witness_db_migrate_v2s12(f13.w) == -1,
              "version 13 migrated"); OK();
        CHECK(nodus_witness_db_schema_version(f13.w, &ver) == 0 &&
              ver == 13, "version 13 mutated"); OK();
        CHECK(has_table(f13.w->db, "v2_claim_bytes") == 0,
              "version 13 got a claim table"); OK();
        fx_close(&f13);
    }

    /* apply-side: phase 12c persistence + F49 rollback. */
    if (run_s12_apply_matrix() != 0) return 1;

    printf("test_v2_schema: ALL %d checks passed\n", g_checks);
    return 0;
}
