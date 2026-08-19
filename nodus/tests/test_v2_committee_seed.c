/**
 * @file nodus/tests/test_v2_committee_seed.c
 * @brief Ledger V2 O15E Faz A — the successor committee seed source.
 *
 * Closes ACTIVATION OBLIGATION 2 (nodus_witness_v2_epoch.h): on a
 * SUCCESSOR chain, nodus_committee_compute_for_epoch's state_seed comes
 * from the committed `v2_blocks` BlockID at the lookback height, NEVER
 * from the terminal legacy `blocks` table, and an unusable seed row
 * fails closed. Legacy chains keep the byte-identical legacy read.
 *
 * Driven through the REAL production functions
 * (nodus_committee_compute_for_epoch / nodus_witness_vset_commit_next)
 * over real committed fixtures — no parallel test-only selector. The
 * expected committee order is derived INDEPENDENTLY in this file from
 * the documented tiebreak (SHA3-512(0x02 ‖ pubkey ‖ seed), ascending,
 * within tied-stake groups) so the assertions cannot pass by echoing
 * the implementation's output back at itself.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "crypto/hash/qgp_sha3.h"

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_v2_claims.h"   /* nodus_witness_v2_chain_id */
#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_types.h"

#include "dnac/dnac.h"
#include "dnac/block_v2.h"
#include "dnac/validator.h"

#include "../tests/v2_genesis_fixture.h"

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

/* ── fixture ────────────────────────────────────────────────────────── */

#define N_VAL 9   /* 9 tied-stake candidates for a 7-seat committee     */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain_id[32];
    uint8_t          genesis_id[64];
    uint8_t          pks[N_VAL][DNAC_PUBKEY_SIZE];
} fixture_t;

static void rmrf(const char *path) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    if (system(cmd) != 0) { /* best effort */ }
}

static int run_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK ? 0 : -1;
}

static int seed_validators(fixture_t *fx) {
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < N_VAL; i++) {
        /* Deterministic patterned pubkeys — the seed path verifies no
         * signature, and distinct bytes are all the tiebreak needs. */
        for (size_t b = 0; b < DNAC_PUBKEY_SIZE; b++)
            fx->pks[i][b] = (uint8_t)(0x11 * (i + 1) + (b & 0x3F));

        dnac_validator_record_t v;
        memset(&v, 0, sizeof(v));
        memcpy(v.pubkey, fx->pks[i], DNAC_PUBKEY_SIZE);
        v.self_stake         = 0;      /* ALL EQUAL — tiebreak decides
                                        * (0 keeps the CORE supply
                                        * invariant satisfiable with the
                                        * fixture's zero genesis supply) */
        v.status             = DNAC_VALIDATOR_ACTIVE;
        v.active_since_block = 1;      /* constitutional seed set      */
        uint8_t fpr[64];
        if (qgp_sha3_512(fx->pks[i], DNAC_PUBKEY_SIZE, fpr) != 0) return -1;
        for (int b = 0; b < 64; b++) {
            v.unstake_destination_fp[2 * b]     = hexd[fpr[b] >> 4];
            v.unstake_destination_fp[2 * b + 1] = hexd[fpr[b] & 0xF];
        }
        v.unstake_destination_fp[128] = '\0';
        if (nodus_validator_insert(fx->w, &v) != 0) return -1;
    }
    return 0;
}

static int fx_open(fixture_t *fx, const char *tag) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));   /* multi-MB: never on the stack */
    if (!fx->w) return -1;
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_cseed_%s_XXXXXX", tag);
    if (!mkdtemp(fx->dir)) return -1;
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);

    uint8_t cid16[16];
    memset(cid16, 0x6E, sizeof(cid16));
    if (nodus_witness_create_chain_db(fx->w, cid16) != 0) return -1;
    if (nodus_chain_config_db_migrate(fx->w) != 0) return -1;
    if (nodus_witness_db_migrate_v2s9(fx->w) != 0) return -1;

    if (run_sql(fx->w->db,
            "INSERT INTO supply_tracking (id, genesis_supply, total_burned,"
            " total_minted, current_supply, last_tx_hash, last_sequence) "
            "VALUES (1, 0, 0, 0, 0, zeroblob(64), 0)") != 0)
        return -1;

    if (seed_validators(fx) != 0) return -1;
    if (nodus_witness_vset_commit_genesis(fx->w, 1) != 0) return -1;

    uint8_t vset[64];
    memset(vset, 0x77, sizeof(vset));
    if (v2x_genesis_min(fx->w, vset, fx->genesis_id, NULL) != 0) return -1;
    if (nodus_witness_v2_chain_id(fx->w, fx->chain_id) != 0) return -1;

    fx->w->v2_successor = true;
    memcpy(fx->w->v2_chain32, fx->chain_id, 32);
    return 0;
}

static void fx_close(fixture_t *fx) {
    if (fx->w) {
        if (fx->w->db) sqlite3_close(fx->w->db);
        free(fx->w);
        fx->w = NULL;
    }
    if (fx->dir[0]) rmrf(fx->dir);
}

/* ── crafted committed seed rows ────────────────────────────────────── */

/* Build a canonical v3 header at `height` on `chain` and insert the row
 * exactly as the engine persists it (block_id = the header-recomputed
 * BlockID unless `forge_id` overrides it). */
static int plant_v2_row(nodus_witness_t *w, uint64_t height,
                        const uint8_t chain[32],
                        const uint8_t *forge_id /* NULL = honest */,
                        uint64_t header_height_override /* 0 = height */,
                        uint8_t out_id[64]) {
    dna_block_header_v2_t h;
    memset(&h, 0, sizeof(h));
    h.header_version = DNA_BH2_VERSION;
    memcpy(h.chain_id, chain, 32);
    h.block_height = header_height_override ? header_height_override
                                            : height;
    h.epoch = h.block_height / (uint64_t)DNAC_EPOCH_LENGTH;
    memset(h.prev_block_id,       0x21, 64);
    memset(h.global_state_root,   0x22, 64);
    memset(h.tx_root,             0x23, 64);
    memset(h.domain_updates_root, 0x24, 64);
    memset(h.validator_set_hash,  0x25, 64);
    h.tx_count  = 0;
    h.timestamp = 0;

    uint8_t enc[DNA_BH2_ENC_SIZE];
    uint8_t id[DNA_BH2_ID_LEN];
    if (dna_bh2_encode(&h, enc) != 0) return -1;
    if (dna_bh2_block_id(&h, id) != 0) return -1;
    if (forge_id) memcpy(id, forge_id, 64);

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_blocks (global_height, block_id, prev_block_id,"
            " epoch, tx_root, domain_updates_root, domains_root,"
            " global_root, vset_hash, tx_count, header, qc) "
            "VALUES (?1, ?2, zeroblob(64), ?3, zeroblob(64), zeroblob(64),"
            " zeroblob(64), zeroblob(64), zeroblob(64), 0, ?4, NULL)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)height);
    sqlite3_bind_blob (st, 2, id, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)h.epoch);
    sqlite3_bind_blob (st, 4, enc, DNA_BH2_ENC_SIZE, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;
    if (out_id) memcpy(out_id, id, 64);
    return 0;
}

static int drop_v2_row(nodus_witness_t *w, uint64_t height) {
    char sql[96];
    snprintf(sql, sizeof(sql),
             "DELETE FROM v2_blocks WHERE global_height = %llu",
             (unsigned long long)height);
    return run_sql(w->db, sql);
}

static int plant_legacy_row(nodus_witness_t *w, uint64_t height,
                            uint8_t fill) {
    sqlite3_stmt *st = NULL;
    uint8_t root[64];
    memset(root, fill, sizeof(root));
    if (sqlite3_prepare_v2(w->db,
            "INSERT OR REPLACE INTO blocks (height, tx_root, tx_count,"
            " timestamp, prev_hash, state_root) "
            "VALUES (?1, zeroblob(64), 0, 0, zeroblob(64), ?2)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)height);
    sqlite3_bind_blob (st, 2, root, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* ── the INDEPENDENT expected order ─────────────────────────────────── */

/* All fixture stakes are equal, so the whole candidate set is ONE tied
 * group: expected order = tiebreak ASC, where
 * tiebreak = SHA3-512(0x02 ‖ pubkey ‖ seed). Derived here from the
 * documented rule, not from the implementation's helpers. */
static void expected_order(const fixture_t *fx, const uint8_t seed[64],
                           int order_out[N_VAL]) {
    uint8_t tb[N_VAL][64];
    uint8_t buf[1 + DNAC_PUBKEY_SIZE + 64];
    for (int i = 0; i < N_VAL; i++) {
        buf[0] = NODUS_TREE_TAG_VALIDATOR;
        memcpy(&buf[1], fx->pks[i], DNAC_PUBKEY_SIZE);
        memcpy(&buf[1 + DNAC_PUBKEY_SIZE], seed, 64);
        (void)qgp_sha3_512(buf, sizeof(buf), tb[i]);
        order_out[i] = i;
    }
    for (int a = 0; a < N_VAL; a++)
        for (int b = a + 1; b < N_VAL; b++)
            if (memcmp(tb[order_out[b]], tb[order_out[a]], 64) < 0) {
                int t = order_out[a];
                order_out[a] = order_out[b];
                order_out[b] = t;
            }
}

static int committee_matches(const fixture_t *fx,
                             const nodus_committee_member_t *got, int n,
                             const int order[N_VAL]) {
    if (n > N_VAL) return 0;
    for (int i = 0; i < n; i++)
        if (memcmp(got[i].pubkey, fx->pks[order[i]], DNAC_PUBKEY_SIZE) != 0)
            return 0;
    return 1;
}

/* ── main ───────────────────────────────────────────────────────────── */

int main(void) {
    fixture_t fx;
    CHECK(fx_open(&fx, "m") == 0, "fixture open"); OK();

    const uint64_t E        = (uint64_t)DNAC_EPOCH_LENGTH;
    const uint64_t E_START  = 2 * E;          /* first non-bootstrap epoch */
    const uint64_t LOOKBACK = E_START - E - 1;

    nodus_committee_member_t *out =
        calloc((size_t)DNAC_MAX_ACTIVE_VALIDATORS, sizeof(*out));
    CHECK(out != NULL, "member buffer");
    int count = 0;

    /* §1 — MISSING seed row fails closed, digest unchanged. */
    {
        uint8_t d0[64], d1[64];
        CHECK(v2x_db_digest(fx.w, d0) == 0, "digest before"); OK();
        CHECK(nodus_committee_compute_for_epoch(fx.w, E_START, out,
                  DNAC_MAX_ACTIVE_VALIDATORS, &count) == -1,
              "missing V2 seed row must fail closed"); OK();
        CHECK(v2x_db_digest(fx.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
              "failed compute left the DB byte-identical"); OK();
    }

    /* §2 — the committed V2 BlockID is the seed; the terminal legacy
     * table is DEAD on a successor. */
    uint8_t seed_id[64];
    {
        CHECK(plant_v2_row(fx.w, LOOKBACK, fx.chain_id, NULL, 0,
                           seed_id) == 0, "plant V2 seed row"); OK();
        /* poison the legacy table at the same height BEFORE computing */
        CHECK(plant_legacy_row(fx.w, LOOKBACK, 0xAA) == 0,
              "plant poisoned legacy row"); OK();

        int ord_v2[N_VAL], ord_legacy[N_VAL];
        expected_order(&fx, seed_id, ord_v2);
        uint8_t legacy_root[64];
        memset(legacy_root, 0xAA, sizeof(legacy_root));
        expected_order(&fx, legacy_root, ord_legacy);
        /* vacuity guard: the two seeds must order the set differently,
         * otherwise "ignored the legacy row" would be unobservable */
        CHECK(memcmp(ord_v2, ord_legacy, sizeof(ord_v2)) != 0,
              "fixture must discriminate the two seeds"); OK();

        CHECK(nodus_committee_compute_for_epoch(fx.w, E_START, out,
                  DNAC_MAX_ACTIVE_VALIDATORS, &count) == 0,
              "compute with committed V2 seed"); OK();
        CHECK(count == DNAC_COMMITTEE_SIZE, "target-size committee"); OK();
        CHECK(committee_matches(&fx, out, count, ord_v2),
              "order follows the V2 BlockID seed"); OK();
        CHECK(!committee_matches(&fx, out, count, ord_legacy),
              "order does NOT follow the poisoned legacy root"); OK();

        /* mutate the legacy row — the successor result must not move */
        CHECK(plant_legacy_row(fx.w, LOOKBACK, 0xBB) == 0,
              "mutate legacy row"); OK();
        CHECK(nodus_committee_compute_for_epoch(fx.w, E_START, out,
                  DNAC_MAX_ACTIVE_VALIDATORS, &count) == 0 &&
              committee_matches(&fx, out, count, ord_v2),
              "legacy mutation is invisible on a successor"); OK();

        /* delete the legacy row — still identical */
        CHECK(run_sql(fx.w->db, "DELETE FROM blocks") == 0,
              "drop legacy rows"); OK();
        CHECK(nodus_committee_compute_for_epoch(fx.w, E_START, out,
                  DNAC_MAX_ACTIVE_VALIDATORS, &count) == 0 &&
              committee_matches(&fx, out, count, ord_v2),
              "legacy absence is invisible on a successor"); OK();
    }

    /* §3 — fail-closed matrix over unusable seed rows. */
    {
        uint8_t d0[64], d1[64];

        /* short block_id */
        CHECK(drop_v2_row(fx.w, LOOKBACK) == 0, "drop"); OK();
        CHECK(plant_v2_row(fx.w, LOOKBACK, fx.chain_id, NULL, 0,
                           NULL) == 0, "replant"); OK();
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(fx.w->db,
                      "UPDATE v2_blocks SET block_id = zeroblob(63) "
                      "WHERE global_height = ?1", -1, &st, NULL)
                      == SQLITE_OK, "prep shorten");
            sqlite3_bind_int64(st, 1, (sqlite3_int64)LOOKBACK);
            CHECK(sqlite3_step(st) == SQLITE_DONE, "shorten id");
            sqlite3_finalize(st);
            OK();
        }
        CHECK(v2x_db_digest(fx.w, d0) == 0, "digest"); OK();
        CHECK(nodus_committee_compute_for_epoch(fx.w, E_START, out,
                  DNAC_MAX_ACTIVE_VALIDATORS, &count) == -1,
              "short block_id fails closed"); OK();
        CHECK(v2x_db_digest(fx.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
              "no write on the short-id reject"); OK();

        /* truncated header */
        CHECK(drop_v2_row(fx.w, LOOKBACK) == 0 &&
              plant_v2_row(fx.w, LOOKBACK, fx.chain_id, NULL, 0,
                           NULL) == 0, "replant"); OK();
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(fx.w->db,
                      "UPDATE v2_blocks SET header = substr(header, 1, 412) "
                      "WHERE global_height = ?1", -1, &st, NULL)
                      == SQLITE_OK, "prep trunc");
            sqlite3_bind_int64(st, 1, (sqlite3_int64)LOOKBACK);
            CHECK(sqlite3_step(st) == SQLITE_DONE, "truncate header");
            sqlite3_finalize(st);
            OK();
        }
        CHECK(nodus_committee_compute_for_epoch(fx.w, E_START, out,
                  DNAC_MAX_ACTIVE_VALIDATORS, &count) == -1,
              "truncated header fails closed"); OK();

        /* retired header version byte (2) — strict decode rejects */
        CHECK(drop_v2_row(fx.w, LOOKBACK) == 0 &&
              plant_v2_row(fx.w, LOOKBACK, fx.chain_id, NULL, 0,
                           NULL) == 0, "replant"); OK();
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(fx.w->db,
                      "UPDATE v2_blocks SET header = "
                      " x'02' || substr(header, 2) "
                      "WHERE global_height = ?1", -1, &st, NULL)
                      == SQLITE_OK, "prep ver");
            sqlite3_bind_int64(st, 1, (sqlite3_int64)LOOKBACK);
            CHECK(sqlite3_step(st) == SQLITE_DONE, "retire version byte");
            sqlite3_finalize(st);
            OK();
        }
        CHECK(nodus_committee_compute_for_epoch(fx.w, E_START, out,
                  DNAC_MAX_ACTIVE_VALIDATORS, &count) == -1,
              "retired header version fails closed"); OK();

        /* WRONG CHAIN: header self-consistent (id recomputed over it)
         * but for a foreign chain id */
        CHECK(drop_v2_row(fx.w, LOOKBACK) == 0, "drop"); OK();
        {
            uint8_t foreign[32];
            memset(foreign, 0x99, sizeof(foreign));
            CHECK(plant_v2_row(fx.w, LOOKBACK, foreign, NULL, 0,
                               NULL) == 0, "plant foreign-chain row"); OK();
        }
        CHECK(nodus_committee_compute_for_epoch(fx.w, E_START, out,
                  DNAC_MAX_ACTIVE_VALIDATORS, &count) == -1,
              "wrong-chain seed row fails closed"); OK();

        /* FORGED id: header honest, stored id substituted */
        CHECK(drop_v2_row(fx.w, LOOKBACK) == 0, "drop"); OK();
        {
            uint8_t forged[64];
            memset(forged, 0x5A, sizeof(forged));
            CHECK(plant_v2_row(fx.w, LOOKBACK, fx.chain_id, forged, 0,
                               NULL) == 0, "plant forged-id row"); OK();
        }
        CHECK(nodus_committee_compute_for_epoch(fx.w, E_START, out,
                  DNAC_MAX_ACTIVE_VALIDATORS, &count) == -1,
              "forged block_id fails closed"); OK();

        /* header height disagreeing with the row key */
        CHECK(drop_v2_row(fx.w, LOOKBACK) == 0, "drop"); OK();
        CHECK(plant_v2_row(fx.w, LOOKBACK, fx.chain_id, NULL,
                           LOOKBACK + 1, NULL) == 0,
              "plant height-mismatched row"); OK();
        CHECK(nodus_committee_compute_for_epoch(fx.w, E_START, out,
                  DNAC_MAX_ACTIVE_VALIDATORS, &count) == -1,
              "header/row height mismatch fails closed"); OK();

        /* restore the honest row for the sections below */
        CHECK(drop_v2_row(fx.w, LOOKBACK) == 0 &&
              plant_v2_row(fx.w, LOOKBACK, fx.chain_id, NULL, 0,
                           seed_id) == 0, "restore honest row"); OK();
    }

    /* §4 — lookback 0 (e_start == E+1, direct call): the committed
     * successor GENESIS row is the seed. */
    {
        int ord_gen[N_VAL];
        expected_order(&fx, fx.genesis_id, ord_gen);
        CHECK(nodus_committee_compute_for_epoch(fx.w, E + 1, out,
                  DNAC_MAX_ACTIVE_VALIDATORS, &count) == 0,
              "lookback-0 compute over the genesis row"); OK();
        CHECK(committee_matches(&fx, out, count, ord_gen),
              "lookback-0 order follows the genesis BlockID"); OK();
    }

    /* §5 — commit_next drives the same path: absent seed fails the
     * boundary step with NO snapshot row; present seed commits one. */
    {
        uint8_t d0[64], d1[64];
        CHECK(drop_v2_row(fx.w, LOOKBACK) == 0, "drop seed row"); OK();
        CHECK(v2x_db_digest(fx.w, d0) == 0, "digest"); OK();
        CHECK(nodus_witness_vset_commit_next(fx.w, E) == -1,
              "commit_next without a V2 seed fails closed"); OK();
        CHECK(v2x_db_digest(fx.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
              "failed commit_next wrote nothing"); OK();

        CHECK(plant_v2_row(fx.w, LOOKBACK, fx.chain_id, NULL, 0,
                           NULL) == 0, "replant seed row"); OK();
        CHECK(nodus_witness_vset_commit_next(fx.w, E) == 0,
              "commit_next with the V2 seed commits"); OK();
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(fx.w->db,
                      "SELECT COUNT(*) FROM validator_set_snapshots "
                      "WHERE epoch_start = ?1", -1, &st, NULL)
                      == SQLITE_OK, "prep snap count");
            sqlite3_bind_int64(st, 1, (sqlite3_int64)E_START);
            CHECK(sqlite3_step(st) == SQLITE_ROW &&
                  sqlite3_column_int64(st, 0) == 1,
                  "epoch-2E snapshot row exists");
            sqlite3_finalize(st);
            OK();
        }
    }

    /* §6 — reopen determinism: a fresh handle over the same committed
     * bytes recomputes the identical committee. */
    {
        int ord_v2[N_VAL];
        expected_order(&fx, seed_id, ord_v2);
        /* capture, close, reopen */
        char dir[128];
        snprintf(dir, sizeof(dir), "%s", fx.dir);
        sqlite3_close(fx.w->db);
        free(fx.w);
        fx.w = calloc(1, sizeof(*fx.w));
        CHECK(fx.w != NULL, "realloc witness"); OK();
        fx.w->cached_committee_epoch_start = UINT64_MAX;
        snprintf(fx.w->data_path, sizeof(fx.w->data_path), "%s", dir);
        uint8_t cid16[16];
        memset(cid16, 0x6E, sizeof(cid16));
        CHECK(nodus_witness_create_chain_db(fx.w, cid16) == 0,
              "reopen chain db"); OK();
        fx.w->v2_successor = true;
        memcpy(fx.w->v2_chain32, fx.chain_id, 32);

        CHECK(nodus_committee_compute_for_epoch(fx.w, E_START, out,
                  DNAC_MAX_ACTIVE_VALIDATORS, &count) == 0 &&
              committee_matches(&fx, out, count, ord_v2),
              "reopen recomputes the identical committee"); OK();
    }

    /* §7 — legacy chains are byte-identical: the legacy read serves the
     * seed and the V2 table is invisible. */
    {
        fixture_t lf;
        CHECK(fx_open(&lf, "l") == 0, "legacy fixture open"); OK();
        lf.w->v2_successor = false;   /* a LEGACY chain */

        CHECK(plant_legacy_row(lf.w, E_START - E - 1, 0xCC) == 0,
              "plant legacy seed row"); OK();
        /* a v2 row also present — must be ignored on a legacy chain */
        CHECK(plant_v2_row(lf.w, E_START - E - 1, lf.chain_id, NULL, 0,
                           NULL) == 0, "plant ignored v2 row"); OK();

        uint8_t legacy_root[64];
        memset(legacy_root, 0xCC, sizeof(legacy_root));
        int ord_legacy[N_VAL];
        expected_order(&lf, legacy_root, ord_legacy);

        CHECK(nodus_committee_compute_for_epoch(lf.w, E_START, out,
                  DNAC_MAX_ACTIVE_VALIDATORS, &count) == 0,
              "legacy compute"); OK();
        CHECK(committee_matches(&lf, out, count, ord_legacy),
              "legacy chain follows the legacy state_root seed"); OK();
        fx_close(&lf);
    }

    free(out);
    fx_close(&fx);
    printf("test_v2_committee_seed: ALL %d CHECKS PASSED\n", g_checks);
    return 0;
}
