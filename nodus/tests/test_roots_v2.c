/**
 * Nodus — Ledger V2 S2: tagged root-hierarchy tests (INACTIVE hierarchy).
 *
 * Every canonical preimage is pinned to a literal computed by an
 * INDEPENDENT implementation (python3 hashlib.sha3_512 — the oracle script
 * and its output are recorded in the S2 season report). Sections:
 *   1. Shared-layer KATs + negatives (empty tags, supply, tokens, epoch v2,
 *      DomainHead, domains_root incl. a THIRD future domain, composition,
 *      subroot mutation sweep, supply-committed-once).
 *   2. Witness loaders over real in-memory SQLite state: token-root
 *      insertion-order independence, duplicate/malformed/fail-closed,
 *      pre-genesis empty states.
 *   3. 7/7 determinism: seven independent witness instances with identical
 *      state compute identical SYSTEM/CORE/domains/global roots.
 *
 * @file test_roots_v2.c
 */

#include "dnac/ledger_roots_v2.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness.h"
#include "nodus/nodus_chain_config.h"
#include "witness/nodus_witness_db.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

static void fill(uint8_t *dst, size_t len, uint8_t seed) {
    for (size_t i = 0; i < len; i++) dst[i] = (uint8_t)(seed + i * 7u);
}

static int hex_eq(const uint8_t h[64], const char *hex, const char *what) {
    static const char *d = "0123456789abcdef";
    char got[129];
    for (int i = 0; i < 64; i++) {
        got[2 * i] = d[h[i] >> 4]; got[2 * i + 1] = d[h[i] & 0xf];
    }
    got[128] = 0;
    if (strcmp(got, hex) != 0) {
        fprintf(stderr, "KAT mismatch (%s):\n  pinned: %s\n  got:    %s\n",
                what, hex, got);
        return 0;
    }
    return 1;
}

/* Pinned python3-oracle literals (independent sha3_512 implementation). */
static const char *EMPTY_KAT[DNA_V2_EMPTY__COUNT] = {
    /* VSET   */ "fd1c65789de6e38765ae77ca7d302e7a7b95400233ef55218139df9f1b4e63487a3d88706303b0a5b8eeec695526d26d04d0267bcce826c995f2b8a5d8f2261b",
    /* DOMREG */ "107bae9d51c4a1567d25d1e75f1df56e671fac019b6325324407df76429089c0231074520edcbff6bcc01926ba5bcb4d1a905f52ea819be0fb9a9d2c59de74ea",
    /* MANIF  */ "90d5ec18e9745fae481baf31660bfb0b86150c147fb819ce978af5bdc538d8d1ab591defc2cd65334bc667bebd90c5c8cd55a16ae458adb8a9b05b521a4f9c18",
    /* POOLS  */ "fbba0c378530aa1214dbe5d8810c28b7487aba1b7cc6a44c291c62369dc1ae222727e09549ef48cc638c7face48758964b436107b661b91db82fcb308f3d8042",
    /* CLAIMS */ "b34a8d97ef88610cc933751fe9f2a8d61dd60c916f685a5ffc1667ca6c5d4f4abe0fe46a51e40251b859a870f28c6bb342b36cae3c45b525cccbdef051fba6a8",
    /* NAMES  */ "ef12a4d9657dc6711688a664ea0ac0a9295f8bdc595599121a7b60c7dae9467ec3e80e861e55a3cb99c76dfbf14c596e91fa0fa1b7a67317cbc155ce120db412",
    /* TOKENS */ "4098bc465307c3a6340c1374d020957372b82d4b670f5e2049b6a3fa13f9ade608eadcc34afe643079b6e4fcd890bab80f1b4582023e80c719bcffcf0ce093f3",
    /* EPOCH2 */ "e49a53f12820a8589744a67123cfcb9b7e75d8be9197c168b4caee2ed2804cb9a1aee49c9127cc8697fb93982e2d6c1e4ee720f8a75c31a9efc166744159d126",
};
static const char *KAT_SUPPLY       = "ef949407440c0a7adab9f6b0a0999e06074e57a4b2b04f7b1532cf2effb597f2e656e3f396f663a1b3d5237d6709165393ec076ddc5f47f35abe0de3b26e91b7";
static const char *KAT_TOKEN_LEAF_A = "29c4c9998ab9a29fe1a90bbcb021d743287ef733c03d896b67131d07cee9f9ef54347e2d2d64430814f900e804e298d86c085c051c8159d9e8fe471c5e720d47";
static const char *KAT_TOKEN_ROOT   = "0b039f37cdf12fb0c30580bdd338246c393d9d434d686e9f21627152bf545efc8c88e4ddcaef74d0ebef915cbed1d293c45559ae84325e56cdd7d0f2e7bbb9d7";
static const char *KAT_EPOCH_LEAF1  = "d8015bdc11119bed60d273b1c4089018513a29997765eac3d905b866264b237b20225f69f17060ab342eb557ca4bf1a79c1be7d5ab59dc42b99a92e45a31c468";
static const char *KAT_EPOCH_ROOT   = "1837965787d805678abfe86ea24e898546a3e7d1712485098612abd8026eb5b0bad03b645aa96207776b4a60d3f7cb4d1fc3f682d0a68d7184ba7fd78396b1cd";
static const char *KAT_DOMHEAD_SYS  = "e675d070c918dedf23fa5d1ebf8d2381345705b316ffb1340e85738b50b6e01d7753a3e0ef456f3ff588fddcd4bba1c35a1edf7274ee46c48d2bd988b645b0b5";
static const char *KAT_DOMAINS_2    = "bba32c948f2851a85dae113c7b27258d27f4a292ee423faca3a072f5e31634bcd80bb608386d0b664c934db4997539b0c02599c8ee1a5430dea4e5d68430838a";
static const char *KAT_DOMAINS_3    = "823492dabf1bddd0b76b907d31233e4affeaf5b4f85caaccf55488eb5f6af5ad04d3c7993d38472887915535ec6a6cd608d8688ac8c7d6daa40efd0105c97d4e";
static const char *KAT_SYSTEM       = "673b7a1e99ad40c4a41d3a9484043ea8f157fe428ccdf988d4a57f7f4ca15fad13685758c4698d1f549890cbe1d6378f7035af69733ce0679c44008afc0a8eae";
static const char *KAT_CORE         = "b35098ed2cedf5e19f2921e9226a952327cbc22247cfca205cd81c2ca6d775a54da830eba59804df2d42446ba384f8daf6e3e601887b6cada1f8b00a7981ab21";
static const char *KAT_GLOBAL       = "0c0d2fce1984bf15c2e5841eeef72a067aefe4cdf8790a713332f09326393f79185dc7277f3d403a6f9d47fbfc68b049ddb117a654f2da59e0e4218e45f7e681";

/* ── Fixture token leaves (must mirror the oracle) ──────────────────── */
static void make_tokens(dna_v2_token_leaf_t t[3],
                        char cfp_a[129], char cfp_b[129], char cfp_c[129]) {
    memset(t, 0, 3 * sizeof(*t));
    memset(cfp_a, 0, 129); memset(cfp_b, 0, 129); memset(cfp_c, 0, 129);
    for (int i = 0; i < 128; i += 2) {
        cfp_a[i] = 'a'; cfp_a[i + 1] = 'a';
        cfp_b[i] = 'b'; cfp_b[i + 1] = 'b';
        cfp_c[i] = 'c'; cfp_c[i + 1] = 'c';
    }
    fill(t[0].token_id, 64, 0x10);
    t[0].name = "Alpha"; t[0].name_len = 5;
    t[0].symbol = "ALP"; t[0].symbol_len = 3;
    t[0].creator_fp = cfp_a; t[0].creator_fp_len = 128;
    t[0].decimals = 8; t[0].flags = 0; t[0].supply = 1000;
    t[0].block_height = 42;
    fill(t[1].token_id, 64, 0x20);
    t[1].name = "Beta"; t[1].name_len = 4;
    t[1].symbol = "BET"; t[1].symbol_len = 3;
    t[1].creator_fp = cfp_b; t[1].creator_fp_len = 128;
    t[1].decimals = 6; t[1].flags = 1; t[1].supply = 999999;
    t[1].block_height = 100;
    fill(t[2].token_id, 64, 0x30);
    t[2].name = "Gamma"; t[2].name_len = 5;
    t[2].symbol = "GAM"; t[2].symbol_len = 3;
    t[2].creator_fp = cfp_c; t[2].creator_fp_len = 128;
    t[2].decimals = 0; t[2].flags = 0; t[2].supply = 1;
    t[2].block_height = 7;
}

static int test_shared_layer(void) {
    uint8_t h[64], h2[64];

    /* Empty roots: pinned, nonzero, pairwise distinct. */
    uint8_t empties[DNA_V2_EMPTY__COUNT][64];
    uint8_t zero64[64] = { 0 };
    for (int k = 0; k < DNA_V2_EMPTY__COUNT; k++) {
        CHECK(dna_v2_empty_root((dna_v2_empty_kind_t)k, empties[k]) == 0,
              "empty root");
        CHECK(hex_eq(empties[k], EMPTY_KAT[k], "empty tag"), "empty KAT"); OK();
        CHECK(memcmp(empties[k], zero64, 64) != 0, "empty root is zero"); OK();
    }
    for (int a = 0; a < DNA_V2_EMPTY__COUNT; a++)
        for (int b = a + 1; b < DNA_V2_EMPTY__COUNT; b++) {
            CHECK(memcmp(empties[a], empties[b], 64) != 0,
                  "empty roots not distinct"); OK();
        }

    /* supply_root KAT + single-commitment-point proof: the v2 epoch leaf
     * takes NO supply inputs, so different counters change ONLY supply_root. */
    CHECK(dna_v2_supply_root(100000000000000000ULL, 500, 300, h) == 0, "supply");
    CHECK(hex_eq(h, KAT_SUPPLY, "supply"), "supply KAT"); OK();
    CHECK(dna_v2_supply_root(100000000000000000ULL, 501, 300, h2) == 0 &&
          memcmp(h, h2, 64) != 0, "minted not bound in supply_root"); OK();
    {
        uint8_t snap[64], e1[64], e1b[64];
        fill(snap, 64, 0x40);
        CHECK(dna_v2_epoch_leaf_hash(720, 5000, snap, e1) == 0, "ep leaf");
        CHECK(hex_eq(e1, KAT_EPOCH_LEAF1, "epoch leaf"), "epoch leaf KAT"); OK();
        /* No supply parameter exists on the v2 leaf — recompute equality
         * documents the relocation (supply committed exactly once). */
        CHECK(dna_v2_epoch_leaf_hash(720, 5000, snap, e1b) == 0 &&
              memcmp(e1, e1b, 64) == 0, "epoch leaf determinism"); OK();

        uint8_t snap2[64], e2[64];
        fill(snap2, 64, 0x50);
        CHECK(dna_v2_epoch_leaf_hash(1440, 6000, snap2, e2) == 0, "ep leaf2");
        uint64_t starts[2] = { 720, 1440 };
        uint8_t leaves[2][64];
        memcpy(leaves[0], e1, 64); memcpy(leaves[1], e2, 64);
        CHECK(dna_v2_epoch_root(starts, leaves, 2, h) == 0, "ep root");
        CHECK(hex_eq(h, KAT_EPOCH_ROOT, "epoch root"), "epoch root KAT"); OK();
        uint64_t dup[2] = { 720, 720 };
        CHECK(dna_v2_epoch_root(dup, leaves, 2, h) != 0,
              "duplicate epoch accepted"); OK();
    }

    /* Tokens: leaf + root KATs, order/duplicate rejection, field mutation. */
    {
        dna_v2_token_leaf_t t[3];
        char ca[129], cb[129], cc[129];
        make_tokens(t, ca, cb, cc);
        CHECK(dna_v2_token_leaf_hash(&t[0], h) == 0, "tok leaf");
        CHECK(hex_eq(h, KAT_TOKEN_LEAF_A, "token leaf A"), "tok leaf KAT"); OK();
        CHECK(dna_v2_token_root(t, 3, h) == 0, "tok root");
        CHECK(hex_eq(h, KAT_TOKEN_ROOT, "token root"), "tok root KAT"); OK();

        dna_v2_token_leaf_t bad[3] = { t[1], t[0], t[2] };  /* unsorted */
        CHECK(dna_v2_token_root(bad, 3, h) != 0, "unsorted accepted"); OK();
        dna_v2_token_leaf_t dup[2] = { t[0], t[0] };        /* duplicate */
        CHECK(dna_v2_token_root(dup, 2, h) != 0, "duplicate accepted"); OK();

        /* Every leaf field is bound. */
        dna_v2_token_leaf_t m = t[0];
        m.supply ^= 1;
        CHECK(dna_v2_token_leaf_hash(&m, h2) == 0 &&
              memcmp(h, h2, 64) != 0, "supply not bound"); OK();
        m = t[0]; m.decimals ^= 1;
        CHECK(dna_v2_token_leaf_hash(&m, h2) == 0, "hash");
        uint8_t href[64];
        CHECK(dna_v2_token_leaf_hash(&t[0], href) == 0 &&
              memcmp(href, h2, 64) != 0, "decimals not bound"); OK();
        m = t[0]; m.flags ^= 1;
        CHECK(dna_v2_token_leaf_hash(&m, h2) == 0 &&
              memcmp(href, h2, 64) != 0, "flags not bound"); OK();
        m = t[0]; m.block_height ^= 1;
        CHECK(dna_v2_token_leaf_hash(&m, h2) == 0 &&
              memcmp(href, h2, 64) != 0, "height not bound"); OK();
        m = t[0]; m.name = "Alphb";
        CHECK(dna_v2_token_leaf_hash(&m, h2) == 0 &&
              memcmp(href, h2, 64) != 0, "name not bound"); OK();
        m = t[0]; m.symbol = "ALQ";
        CHECK(dna_v2_token_leaf_hash(&m, h2) == 0 &&
              memcmp(href, h2, 64) != 0, "symbol not bound"); OK();
        m = t[0]; ca[0] = 'x';
        CHECK(dna_v2_token_leaf_hash(&m, h2) == 0 &&
              memcmp(href, h2, 64) != 0, "creator not bound"); OK();
        ca[0] = 'a';
    }

    /* DomainHead + domains_root: KATs, generic third domain, negatives,
     * untouched-head byte identity. */
    {
        dna_v2_domain_head_t d[3];
        memset(d, 0, sizeof(d));
        d[0].domain_id = 0; fill(d[0].domain_state_root, 64, 0x60);
        d[0].ruleset_version = 1;
        d[1].domain_id = 1; fill(d[1].domain_state_root, 64, 0x70);
        d[1].ruleset_version = 1;
        d[2].domain_id = 7; fill(d[2].domain_state_root, 64, 0x80);
        d[2].domain_height = 3; d[2].last_updated_global_height = 9;
        d[2].ruleset_version = 2; d[2].status = 1;

        CHECK(dna_v2_domain_head_hash(&d[0], h) == 0, "domhead");
        CHECK(hex_eq(h, KAT_DOMHEAD_SYS, "domhead"), "domhead KAT"); OK();
        CHECK(dna_v2_domains_root(d, 2, h) == 0, "domains2");
        CHECK(hex_eq(h, KAT_DOMAINS_2, "domains2"), "domains2 KAT"); OK();
        /* GENERIC: a future third domain needs no format change. */
        CHECK(dna_v2_domains_root(d, 3, h) == 0, "domains3");
        CHECK(hex_eq(h, KAT_DOMAINS_3, "domains3"), "domains3 KAT"); OK();

        /* Untouched head → byte-identical encoding + hash. */
        uint8_t e1[DNA_V2_DOMHEAD_ENC_LEN], e2[DNA_V2_DOMHEAD_ENC_LEN];
        CHECK(dna_v2_domain_head_encode(&d[1], e1) == 0 &&
              dna_v2_domain_head_encode(&d[1], e2) == 0 &&
              memcmp(e1, e2, sizeof(e1)) == 0, "untouched head drifted"); OK();

        dna_v2_domain_head_t bad2[2] = { d[1], d[0] };      /* unsorted */
        CHECK(dna_v2_domains_root(bad2, 2, h) != 0, "unsorted domains"); OK();
        dna_v2_domain_head_t dup2[2] = { d[0], d[0] };      /* duplicate */
        CHECK(dna_v2_domains_root(dup2, 2, h) != 0, "dup domains"); OK();
        dna_v2_domain_head_t nosys[2] = { d[1], d[2] };     /* no SYSTEM */
        CHECK(dna_v2_domains_root(nosys, 2, h) != 0, "SYSTEM missing ok'd"); OK();
        CHECK(dna_v2_domains_root(d, 0, h) != 0, "empty domains ok'd"); OK();
    }

    /* Composition KATs + full subroot mutation sweep. */
    {
        uint8_t legs[8][64];
        for (int i = 0; i < 8; i++) fill(legs[i], 64, (uint8_t)(0x90 + i));
        CHECK(dna_v2_system_root(legs[0], legs[1], legs[2], legs[3], legs[4],
                                 legs[5], legs[6], legs[7], h) == 0, "sys");
        CHECK(hex_eq(h, KAT_SYSTEM, "system"), "system KAT"); OK();
        for (int i = 0; i < 8; i++) {
            legs[i][0] ^= 1;
            CHECK(dna_v2_system_root(legs[0], legs[1], legs[2], legs[3],
                                     legs[4], legs[5], legs[6], legs[7],
                                     h2) == 0 && memcmp(h, h2, 64) != 0,
                  "system leg not bound"); OK();
            legs[i][0] ^= 1;
        }
        uint8_t cl[5][64];
        for (int i = 0; i < 5; i++) fill(cl[i], 64, (uint8_t)(0xB0 + i));
        CHECK(dna_v2_core_root(cl[0], cl[1], cl[2], cl[3], cl[4], h) == 0,
              "core");
        CHECK(hex_eq(h, KAT_CORE, "core"), "core KAT"); OK();
        for (int i = 0; i < 5; i++) {
            cl[i][0] ^= 1;
            CHECK(dna_v2_core_root(cl[0], cl[1], cl[2], cl[3], cl[4], h2) == 0
                  && memcmp(h, h2, 64) != 0, "core leg not bound"); OK();
            cl[i][0] ^= 1;
        }
        uint8_t dr[64];
        fill(dr, 64, 0xC5);
        CHECK(dna_v2_global_root(dr, h) == 0, "global");
        CHECK(hex_eq(h, KAT_GLOBAL, "global"), "global KAT"); OK();
        dr[0] ^= 1;
        CHECK(dna_v2_global_root(dr, h2) == 0 && memcmp(h, h2, 64) != 0,
              "domains_root not bound"); OK();
    }
    return 0;
}

/* ── Witness-loader fixtures ────────────────────────────────────────── */

static int run_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "sql failed: %s\n", err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

/* Production tokens schema (nodus_witness.c) — hand-created per the
 * established witness-test pattern (test_witness_merkle.c). */
static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS tokens ("
    "  token_id BLOB PRIMARY KEY, name TEXT NOT NULL, symbol TEXT NOT NULL,"
    "  decimals INTEGER NOT NULL DEFAULT 8, supply INTEGER NOT NULL,"
    "  creator_fp TEXT NOT NULL, flags INTEGER NOT NULL DEFAULT 0,"
    "  block_height INTEGER NOT NULL DEFAULT 0,"
    "  timestamp INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE IF NOT EXISTS epoch_state ("
    "  epoch_start_height INTEGER PRIMARY KEY,"
    "  epoch_pool_accum INTEGER NOT NULL DEFAULT 0,"
    "  snapshot_hash BLOB, snapshot_blob BLOB);"
    "CREATE TABLE IF NOT EXISTS utxo_set ("
    "  nullifier BLOB PRIMARY KEY, owner TEXT NOT NULL,"
    "  amount INTEGER NOT NULL,"
    "  token_id BLOB NOT NULL, tx_hash BLOB NOT NULL,"
    "  output_index INTEGER NOT NULL,"
    "  block_height INTEGER NOT NULL DEFAULT 0,"
    "  created_at INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE IF NOT EXISTS validators ("
    "  pubkey BLOB PRIMARY KEY, self_stake INTEGER NOT NULL,"
    "  total_delegated INTEGER NOT NULL DEFAULT 0,"
    "  external_delegated INTEGER NOT NULL DEFAULT 0,"
    "  commission_bps INTEGER NOT NULL DEFAULT 0,"
    "  pending_commission_bps INTEGER NOT NULL DEFAULT 0,"
    "  pending_effective_block INTEGER NOT NULL DEFAULT 0,"
    "  status INTEGER NOT NULL DEFAULT 0,"
    "  active_since_block INTEGER NOT NULL DEFAULT 0,"
    "  unstake_commit_block INTEGER NOT NULL DEFAULT 0,"
    "  unstake_destination_fp BLOB,"
    "  unstake_destination_pubkey BLOB,"
    "  last_validator_update_block INTEGER NOT NULL DEFAULT 0,"
    "  consecutive_missed_epochs INTEGER NOT NULL DEFAULT 0,"
    "  last_signed_block INTEGER NOT NULL DEFAULT 0,"
    "  signed_blocks_this_epoch INTEGER NOT NULL DEFAULT 0);"
    "CREATE TABLE IF NOT EXISTS delegations ("
    "  delegator_pubkey BLOB NOT NULL, validator_pubkey BLOB NOT NULL,"
    "  amount INTEGER NOT NULL, delegated_at_block INTEGER NOT NULL,"
    "  PRIMARY KEY (delegator_pubkey, validator_pubkey));"
    /* S3: nodus_witness_system_root_v2's validator-set leg is no longer a
     * hard-coded tagged empty root — it now reads this table via
     * nodus_witness_vset_root, which fails closed if the table is absent.
     * These fixtures leave it EMPTY, and an empty table yields exactly the
     * DNA_V2_EMPTY_VSET tagged root the S2 placeholder produced, so every
     * expectation in this file is unchanged. Snapshot-bearing coverage
     * lives in test_vset_persist.c. */
    "CREATE TABLE IF NOT EXISTS validator_set_snapshots ("
    "  epoch_start INTEGER PRIMARY KEY, active_count INTEGER NOT NULL,"
    "  snapshot_hash BLOB NOT NULL, snapshot_blob BLOB NOT NULL,"
    "  created_at_height INTEGER NOT NULL);";

static int setup_w(nodus_witness_t **w_out) {
    nodus_witness_t *w = calloc(1, sizeof(*w));   /* multi-MB: heap-alloc */
    if (!w) return -1;
    if (sqlite3_open(":memory:", &w->db) != SQLITE_OK) { free(w); return -1; }
    if (run_sql(w->db, SCHEMA_SQL) != 0) {
        sqlite3_close(w->db); free(w);
        return -1;
    }
    nodus_chain_config_db_migrate(w);   /* creates chain_config_history */
    *w_out = w;
    return 0;
}

static void teardown_w(nodus_witness_t *w) {
    if (!w) return;
    if (w->db) sqlite3_close(w->db);
    free(w);
}

static int insert_token(nodus_witness_t *w, uint8_t id_seed,
                        const char *name, const char *symbol,
                        int decimals, long long supply, const char *cfp,
                        int flags, long long height, long long ts) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO tokens (token_id,name,symbol,decimals,supply,"
            "creator_fp,flags,block_height,timestamp) "
            "VALUES (?,?,?,?,?,?,?,?,?)", -1, &st, NULL) != SQLITE_OK)
        return -1;
    uint8_t tid[64];
    fill(tid, 64, id_seed);
    sqlite3_bind_blob(st, 1, tid, 64, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, name, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 3, symbol, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 4, decimals);
    sqlite3_bind_int64(st, 5, supply);
    sqlite3_bind_text(st, 6, cfp, -1, SQLITE_STATIC);
    sqlite3_bind_int(st, 7, flags);
    sqlite3_bind_int64(st, 8, height);
    sqlite3_bind_int64(st, 9, ts);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int populate_fixture(nodus_witness_t *w, int reversed,
                            long long ts_base) {
    char ca[129], cb[129], cc[129];
    memset(ca, 0, 129); memset(cb, 0, 129); memset(cc, 0, 129);
    for (int i = 0; i < 128; i += 2) {
        ca[i] = 'a'; ca[i + 1] = 'a';
        cb[i] = 'b'; cb[i + 1] = 'b';
        cc[i] = 'c'; cc[i + 1] = 'c';
    }
    /* Insertion order varies; the local-clock ts column varies too — the
     * root must be independent of BOTH. */
    if (!reversed) {
        if (insert_token(w, 0x10, "Alpha", "ALP", 8, 1000, ca, 0, 42,
                         ts_base + 1) != 0) return -1;
        if (insert_token(w, 0x20, "Beta", "BET", 6, 999999, cb, 1, 100,
                         ts_base + 2) != 0) return -1;
        if (insert_token(w, 0x30, "Gamma", "GAM", 0, 1, cc, 0, 7,
                         ts_base + 3) != 0) return -1;
    } else {
        if (insert_token(w, 0x30, "Gamma", "GAM", 0, 1, cc, 0, 7,
                         ts_base + 9) != 0) return -1;
        if (insert_token(w, 0x10, "Alpha", "ALP", 8, 1000, ca, 0, 42,
                         ts_base + 8) != 0) return -1;
        if (insert_token(w, 0x20, "Beta", "BET", 6, 999999, cb, 1, 100,
                         ts_base + 7) != 0) return -1;
    }
    /* Epoch row (fixture values match the oracle set: snapshot = fill 0x40). */
    {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO epoch_state (epoch_start_height, "
                "epoch_pool_accum, snapshot_hash) VALUES (720, 5000, ?)",
                -1, &st, NULL) != SQLITE_OK)
            return -1;
        uint8_t snap[64];
        fill(snap, 64, 0x40);
        sqlite3_bind_blob(st, 1, snap, 64, SQLITE_TRANSIENT);
        int rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) return -1;
    }
    /* Supply row via the production initializer (creates supply_tracking). */
    uint8_t gh[64];
    fill(gh, 64, 0x77);
    if (nodus_witness_supply_init(w, 100000000000000000ULL, gh) != 0)
        return -1;
    return 0;
}

static int test_loaders(void) {
    uint8_t r1[64], r2[64], h[64];

    /* Order independence: two DBs, different insertion order + different
     * local-clock timestamps → identical token_root (ts EXCLUDED). */
    nodus_witness_t *wa = NULL, *wb = NULL;
    CHECK(setup_w(&wa) == 0 && setup_w(&wb) == 0, "setup");
    CHECK(populate_fixture(wa, 0, 1000) == 0, "pop a");
    CHECK(populate_fixture(wb, 1, 555000) == 0, "pop b");
    CHECK(nodus_witness_token_root_v2(wa, r1) == 0, "tok root a");
    CHECK(nodus_witness_token_root_v2(wb, r2) == 0, "tok root b");
    CHECK(memcmp(r1, r2, 64) == 0,
          "insertion order / local ts influenced token_root"); OK();
    /* The DB-loaded root equals the shared-layer oracle-pinned root. */
    CHECK(hex_eq(r1, KAT_TOKEN_ROOT, "db token root"), "db tok KAT"); OK();

    /* Epoch v2 root from DB equals the oracle single-leaf value: with one
     * row (720), root == leaf hash. */
    CHECK(nodus_witness_epoch_root_v2(wa, h) == 0, "ep root");
    CHECK(hex_eq(h, KAT_EPOCH_LEAF1, "db epoch root (1 leaf)"),
          "db epoch KAT"); OK();

    /* Supply root from DB (init writes genesis=1e17, minted=0, burned=0). */
    {
        uint8_t expect[64];
        CHECK(nodus_witness_supply_root_v2(wa, h) == 0, "supply root");
        CHECK(dna_v2_supply_root(100000000000000000ULL, 0, 0, expect) == 0 &&
              memcmp(h, expect, 64) == 0, "db supply root mismatch"); OK();
    }

    /* Full assembly runs on real state. */
    {
        uint8_t g[64], d[64], s[64], c[64];
        CHECK(nodus_witness_global_root_v2(wa, g, d, s, c) == 0, "global");
        uint8_t g2[64];
        CHECK(nodus_witness_global_root_v2(wa, g2, NULL, NULL, NULL) == 0 &&
              memcmp(g, g2, 64) == 0, "global determinism"); OK();
    }

    /* Fail-closed: malformed token row (short token_id) fails the root. */
    {
        nodus_witness_t *wm = NULL;
        CHECK(setup_w(&wm) == 0, "setup m");
        CHECK(run_sql(wm->db,
            "INSERT INTO tokens (token_id,name,symbol,decimals,supply,"
            "creator_fp,flags,block_height,timestamp) "
            "VALUES (x'1122', 'Bad', 'BAD', 8, 1, 'ff', 0, 1, 0)") == 0,
            "insert bad");
        CHECK(nodus_witness_token_root_v2(wm, h) != 0,
              "malformed token row did not fail the root"); OK();
        teardown_w(wm);
    }
    /* Fail-closed: missing tokens table (schema-less DB) fails. */
    {
        nodus_witness_t *we = calloc(1, sizeof(*we));
        CHECK(we != NULL, "alloc");
        CHECK(sqlite3_open(":memory:", &we->db) == SQLITE_OK, "open");
        CHECK(nodus_witness_token_root_v2(we, h) != 0,
              "missing tokens table did not fail"); OK();
        /* Pre-genesis honest-empty states: epoch table absent → tagged
         * empty root; supply row absent → zeros supply root. */
        uint8_t expect[64];
        CHECK(nodus_witness_epoch_root_v2(we, h) == 0 &&
              dna_v2_empty_root(DNA_V2_EMPTY_EPOCH_V2, expect) == 0 &&
              memcmp(h, expect, 64) == 0, "absent epoch table != empty root");
        OK();
        teardown_w(we);
    }
    /* Empty (but present) registries: token_root = tagged empty. */
    {
        nodus_witness_t *w0 = NULL;
        CHECK(setup_w(&w0) == 0, "setup 0");
        uint8_t expect[64];
        CHECK(nodus_witness_token_root_v2(w0, h) == 0 &&
              dna_v2_empty_root(DNA_V2_EMPTY_TOKENS, expect) == 0 &&
              memcmp(h, expect, 64) == 0, "empty registry != tagged empty");
        OK();
        teardown_w(w0);
    }

    teardown_w(wa);
    teardown_w(wb);
    return 0;
}

/* ── 7/7 determinism: seven independent instances, identical state ───── */
static int test_7of7(void) {
    uint8_t g[7][64], d[7][64], s[7][64], c[7][64];
    for (int i = 0; i < 7; i++) {
        nodus_witness_t *w = NULL;
        CHECK(setup_w(&w) == 0, "setup i");
        /* Identical logical state; per-node local clock differs (ts_base)
         * and half the nodes saw a different insertion order — as on a
         * real cluster. */
        CHECK(populate_fixture(w, i & 1, 1000 + i * 7919) == 0, "pop i");
        CHECK(nodus_witness_global_root_v2(w, g[i], d[i], s[i], c[i]) == 0,
              "global i");
        teardown_w(w);
    }
    for (int i = 1; i < 7; i++) {
        CHECK(memcmp(g[0], g[i], 64) == 0, "global_root 7/7 divergence"); OK();
        CHECK(memcmp(d[0], d[i], 64) == 0, "domains_root 7/7 divergence"); OK();
        CHECK(memcmp(s[0], s[i], 64) == 0, "system_root 7/7 divergence"); OK();
        CHECK(memcmp(c[0], c[i], 64) == 0, "core_root 7/7 divergence"); OK();
    }
    printf("7/7 determinism: global=%02x%02x%02x%02x... identical across 7 "
           "independent instances\n", g[0][0], g[0][1], g[0][2], g[0][3]);
    return 0;
}

int main(void) {
    if (test_shared_layer() != 0) return 1;
    if (test_loaders() != 0) return 1;
    if (test_7of7() != 0) return 1;
    printf("test_roots_v2: %d checks OK\n", g_checks);
    return 0;
}
