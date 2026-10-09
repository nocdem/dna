/**
 * @file nodus/tests/test_hf6_migrate.c
 * @brief HF-6 sub-slice 3b — the generation-4 edge and the one-shot
 *        validator migration.
 *
 * Design docs/plans/2026-10-03-hf5-validator-owner-stake-design.md rev 6
 * §7 (migration steps 1-4, 6, 10), §8 (one generation, the 3 -> 4 edge as
 * its own phase); plan tasks/hf6-slice3-plan.md §1 "Migration step
 * placement", §2 "3b", §4 (risks); decisions docs/plans/decisions/
 * 2026-10-08-kurultay-14-hf6-summary.md (K4 accrual merge, K8 Foundation
 * address) and 2026-10-09-kurultay-16-hf6-storage-summary.md (D2: the
 * Foundation rows are exactly active_since_block <= 1). Development
 * trigger: param 16 + the storage vote literal (design §10 item 2, D7).
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  A. DIRECT (nodus_witness_v2_roles_migrate on a hand-built DB, inside a
 *     transaction the test opens):
 *   A1. every migrated row equals a hand-built expectation: validator_id =
 *       dna_validator_id_migrated(chain32, pk); owner = the Foundation for
 *       active_since_block <= 1 rows, SHA3-512(pk) otherwise; bonded rows
 *       10M -> 2M with total/external_delegated += 8M; RETIRING and
 *       UNSTAKED amounts untouched; the roles row carries 2592 x 0x00 and
 *       epoch 0; delegations re-keyed to (SHA3-512(dpk), validator_id) with
 *       amount and delegated_at_block kept; the 8M self-delegation is a
 *       TOP-UP of a pre-H node-key self-delegation when the owner IS the
 *       node key (delegated_at_block unchanged) and a NEW row at H
 *       otherwise — so a Foundation validator with a pre-H node-key
 *       self-delegation ends with two rows (plan D5); the new row's
 *       *_pubkey columns are 2592 bytes (Foundation: delegator 2592 x
 *       0x00); Σself + Σtotal_delegated identical before and after, and
 *       Σdelegations == Σtotal_delegated after; the balance copies of THREE
 *       epochs re-keyed (kind 0 owner = validator_id, kind 1 owner kept),
 *       every amount equal, the row count equal; K4: the Foundation rows'
 *       accruals added to an EXISTING Foundation row, the sources deleted,
 *       every other accrual untouched, Σaccrual equal.
 *   A2. K4 with NO Foundation accrual row: it is created with the source's
 *       amount; a second migration on the migrated DB is a fault with the
 *       DB unchanged; a call in autocommit mode is a fault.
 *   A3. faults (-2, the DB unchanged after the rollback): a bonded row
 *       holding 9M instead of 10M; a balance-copy row whose validator_fp
 *       names no validator; a delegation to a pubkey with no validator
 *       row.
 *  B. ENGINE (the seeded fixture of test_hf4_switch, EVM-enabled build,
 *     param 9 at 3, param 14 at 5, param 16 (storage vote literal) at 8 —
 *     every row before the engine genesis, idle blocks):
 *   B1. blocks 1..6 leave v2_validator_roles empty; block 7 (= H-1)
 *       switches the registry to generation 4 (both runtimes resolve
 *       GEN_STORAGE) AND migrates the seven genesis validators (all
 *       active_since_block 1 -> all Foundation-owned, the compiled
 *       DNAC_HF6_FOUNDATION_OWNER), seven (Foundation, validator_id)
 *       self-delegations of 8M at H, copy(0) re-keyed with equal amounts,
 *       the staked supply equal; the committed H-1 global root equals a
 *       recomputation; block 8 (= H) applies and does not migrate again.
 *       In the default build the compiled owner IS the K8 address.
 *   B2. replay after a crash: a block-7 attempt that faults inside the
 *       migration (a stray roles row planted by hand) leaves the DB
 *       byte-unchanged; with the row removed the replay commits, and the
 *       result is byte-identical (v2x_db_digest) to a twin fixture that
 *       applied block 7 once.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: NODUS_EVM_ENABLED (generation 4 exists only there; the
 * CMake target is registered only in that configuration). Effective
 * heights assume DNAC_EPOCH_LENGTH > 8 (checked). B1's K8 pin runs only
 * when DNAC_HF6_FOUNDATION_OWNER is not overridden at build time.
 * Environment: none.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * One /tmp/test_hf6_migrate_* directory per fixture, removed at its end
 * (left behind when a CHECK aborts).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - A's rows are written by hand (nodus_validator_insert /
 *    nodus_delegation_insert, raw SQL for copies and accruals) — the
 *    shapes the production writers produce, not rows a chain produced.
 *  - B's genesis has no delegations, no accrual and one copy epoch; the
 *    three-epoch copy, K4 and the top-up are proven in A only.
 *  - The H-1 roots in B are pinned by SELF-CONSISTENCY (committed ==
 *    recomputed), and in sub-slice 3b they are computed by the v1 leaf
 *    loaders (the gen-4 loaders are 3d). Nothing here crosses an epoch
 *    boundary after H: the boundary readers of the re-keyed tables are
 *    3d's, and their absence is NOT tested here.
 *  - The "crash" in B2 is a fault the engine rolls back, not a killed
 *    process; it proves the edge is all-or-nothing inside the block's
 *    transaction.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_migrate.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_delegation.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_runtime.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/dnac.h"
#include "dnac/validator.h"
#include "dnac/valbind_wire.h"
#include "crypto/hash/qgp_sha3.h"

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

#define E_LEN     ((uint64_t)DNAC_EPOCH_LENGTH)
#define TEN_M     ((uint64_t)DNAC_SELF_STAKE_AMOUNT)
#define TWO_M     ((uint64_t)DNAC_HF6_STAKE_MIN_DEFAULT)
#define EIGHT_M   (TEN_M - TWO_M)
#define MIL       (1000000ULL * 100000000ULL)       /* 1M NODUS raw     */
#define PKLEN     DNAC_PUBKEY_SIZE

static const uint8_t k_found_compiled[] = DNAC_HF6_FOUNDATION_OWNER;
_Static_assert(sizeof(k_found_compiled) == 64, "64-byte Foundation owner");

/* ══ shared helpers ═══════════════════════════════════════════════════ */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain16[16];
} fixture_t;

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) sqlite3_close(fx->w->db);
    free(fx->w);
    fx->w = NULL;
    char cmd[200];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", fx->dir);
    if (system(cmd) != 0) { /* best effort */ }
}

static int run_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL failed (%s): %s\n", sql, err ? err : "?");
        sqlite3_free(err);
        return -1;
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

/* Σself_stake + Σtotal_delegated — the staked supply term */
static int staked(nodus_witness_t *w, sqlite3_int64 *n) {
    return count_q(w, "SELECT COALESCE(SUM(self_stake),0) + "
                   "COALESCE(SUM(total_delegated),0) FROM validators", n);
}

static void pk_of(uint8_t fill, uint8_t pk[PKLEN]) { memset(pk, fill, PKLEN); }

static int fp_of(uint8_t fill, uint8_t out[64]) {
    uint8_t pk[PKLEN];
    pk_of(fill, pk);
    return qgp_sha3_512(pk, PKLEN, out) == 0 ? 0 : -1;
}

static int vid_of(const uint8_t chain32[32], uint8_t fill, uint8_t out[64]) {
    uint8_t pk[PKLEN];
    pk_of(fill, pk);
    return dna_validator_id_migrated(out, chain32, pk);
}

/* the migration inside a transaction the test owns; COMMIT on 0,
 * ROLLBACK otherwise. @return the migration's rc, or 99 on a SQL error */
static int migrate_tx(nodus_witness_t *w, uint64_t h_next,
                      const uint8_t chain32[32], const uint8_t found[64]) {
    if (run_sql(w->db, "BEGIN IMMEDIATE") != 0) return 99;
    int rc = nodus_witness_v2_roles_migrate(w, h_next, chain32, found);
    if (run_sql(w->db, rc == 0 ? "COMMIT" : "ROLLBACK") != 0) return 99;
    return rc;
}

/* ══ A. the direct layer ════════════════════════════════════════════ */

static int fxd_open(fixture_t *fx, const char *tag) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));      /* multi-MB — ALWAYS heap */
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_hf6_migrate_%s_XXXXXX",
             tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain16, 0x6C, sizeof(fx->chain16));
    return nodus_witness_create_chain_db(fx->w, fx->chain16);
}

static int put_val(nodus_witness_t *w, uint8_t fill, uint8_t status,
                   uint64_t since, uint64_t self, uint64_t deleg) {
    dnac_validator_record_t v;
    memset(&v, 0, sizeof(v));
    pk_of(fill, v.pubkey);
    v.self_stake = self;
    v.total_delegated = deleg;
    v.external_delegated = deleg;
    v.commission_bps = 500;
    v.status = status;
    v.active_since_block = since;
    return nodus_validator_insert(w, &v);
}

static int put_del(nodus_witness_t *w, uint8_t dfill, uint8_t vfill,
                   uint64_t amount, uint64_t at) {
    dnac_delegation_record_t d;
    memset(&d, 0, sizeof(d));
    pk_of(dfill, d.delegator_pubkey);
    pk_of(vfill, d.validator_pubkey);
    d.amount = amount;
    d.delegated_at_block = at;
    return nodus_delegation_insert(w, &d);
}

static int put_copy(nodus_witness_t *w, uint64_t epoch, const uint8_t vfp[64],
                    const uint8_t ofp[64], int kind, uint64_t amount) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "INSERT INTO v2_balance_copy (epoch_start, "
                           "validator_fp, owner_fp, kind, amount) VALUES "
                           "(?1, ?2, ?3, ?4, ?5)", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)epoch);
    sqlite3_bind_blob(st, 2, vfp, 64, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 3, ofp, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, kind);
    sqlite3_bind_int64(st, 5, (sqlite3_int64)amount);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* @return 0 present (*amount) / 1 absent / -1 */
static int get_copy(nodus_witness_t *w, uint64_t epoch, const uint8_t vfp[64],
                    const uint8_t ofp[64], int kind, uint64_t *amount) {
    sqlite3_stmt *st = NULL;
    int ret = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT amount FROM v2_balance_copy WHERE "
                           "epoch_start = ?1 AND validator_fp = ?2 AND "
                           "owner_fp = ?3 AND kind = ?4", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)epoch);
    sqlite3_bind_blob(st, 2, vfp, 64, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 3, ofp, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, kind);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        *amount = (uint64_t)sqlite3_column_int64(st, 0);
        ret = 0;
    } else if (rc == SQLITE_DONE) {
        ret = 1;
    }
    sqlite3_finalize(st);
    return ret;
}

static int put_acc(nodus_witness_t *w, const uint8_t fp[64], uint64_t amount) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "INSERT INTO v2_reward_accrual (owner_fp, "
                           "amount) VALUES (?1, ?2)", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, fp, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)amount);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* @return 0 present (*amount) / 1 absent / -1 */
static int get_acc(nodus_witness_t *w, const uint8_t fp[64],
                   uint64_t *amount) {
    sqlite3_stmt *st = NULL;
    int ret = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT amount FROM v2_reward_accrual "
                           "WHERE owner_fp = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, fp, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        *amount = (uint64_t)sqlite3_column_int64(st, 0);
        ret = 0;
    } else if (rc == SQLITE_DONE) {
        ret = 1;
    }
    sqlite3_finalize(st);
    return ret;
}

/* the stored *_pubkey columns of delegation (dfp, vid): 0 / -1 */
static int get_del_pks(nodus_witness_t *w, const uint8_t dfp[64],
                       const uint8_t vid[64], uint8_t dpk[PKLEN],
                       uint8_t vpk[PKLEN]) {
    sqlite3_stmt *st = NULL;
    int ret = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT delegator_pubkey, validator_pubkey "
                           "FROM delegations WHERE delegator_hash = ?1 AND "
                           "validator_hash = ?2", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, dfp, 64, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, vid, 64, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW &&
        sqlite3_column_bytes(st, 0) == PKLEN &&
        sqlite3_column_bytes(st, 1) == PKLEN) {
        memcpy(dpk, sqlite3_column_blob(st, 0), PKLEN);
        memcpy(vpk, sqlite3_column_blob(st, 1), PKLEN);
        ret = 0;
    }
    sqlite3_finalize(st);
    return ret;
}

/* one migrated validator, checked through the 3a v2 reader */
static int chk_val(nodus_witness_t *w, const uint8_t chain32[32],
                   uint8_t fill, const uint8_t owner[64], uint8_t status,
                   uint64_t self, uint64_t deleg) {
    nodus_v2_validator_row_t *r = calloc(1, sizeof(*r));
    uint8_t vid[64], pk[PKLEN], zero[PKLEN];
    int ok = 0;
    if (!r) return -1;
    pk_of(fill, pk);
    memset(zero, 0, sizeof(zero));
    if (vid_of(chain32, fill, vid) == 0 &&
        nodus_validator_v2_get(w, vid, r) == 0 &&
        memcmp(r->validator_id, vid, 64) == 0 &&
        memcmp(r->owner_fp, owner, 64) == 0 &&
        memcmp(r->rec.pubkey, pk, PKLEN) == 0 &&
        memcmp(r->pending_consensus_pubkey, zero, PKLEN) == 0 &&
        r->consensus_key_effective_epoch == 0 &&
        r->rec.status == status &&
        r->rec.self_stake == self &&
        r->rec.total_delegated == deleg &&
        r->rec.external_delegated == deleg)
        ok = 1;
    free(r);
    return ok ? 0 : -1;
}

/* one delegation (dfp, vid) == (amount, at), through the 3a v2 reader */
static int chk_del(nodus_witness_t *w, const uint8_t dfp[64],
                   const uint8_t vid[64], uint64_t amount, uint64_t at) {
    nodus_v2_delegation_row_t d;
    if (nodus_delegation_v2_get(w, dfp, vid, &d) != 0) return -1;
    return (d.amount == amount && d.delegated_at_block == at) ? 0 : -1;
}

/*
 * A1 — the full expectation. Pubkeys are fill bytes:
 *   0x11 ACTIVE       since 1    10M, deleg 1M  (node-key self-deleg 1M)
 *                                                Foundation
 *   0x22 ELIGIBLE     since 500  10M, deleg 3M  (0xD1 delegates 3M)
 *   0x33 RETIRING     since 1    10M, deleg 0   Foundation, not bonded
 *   0x44 UNSTAKED     since 900   0,  deleg 0
 *   0x55 ACTIVE       since 700  10M, deleg 4M  (node-key self-deleg 4M)
 */
static int t_direct_expected(void) {
    fixture_t fx;
    const uint64_t H = 1000;
    uint8_t chain32[32], F[64];
    memset(chain32, 0x5A, sizeof(chain32));
    memset(F, 0xC3, sizeof(F));                   /* a test owner      */
    CHECK(fxd_open(&fx, "a1") == 0, "fixture DB");
    nodus_witness_t *w = fx.w;

    CHECK(put_val(w, 0x11, DNAC_VALIDATOR_ACTIVE, 1, TEN_M, 1 * MIL) == 0 &&
          put_val(w, 0x22, DNAC_VALIDATOR_ELIGIBLE, 500, TEN_M, 3 * MIL)
              == 0 &&
          put_val(w, 0x33, DNAC_VALIDATOR_RETIRING, 1, TEN_M, 0) == 0 &&
          put_val(w, 0x44, DNAC_VALIDATOR_UNSTAKED, 900, 0, 0) == 0 &&
          put_val(w, 0x55, DNAC_VALIDATOR_ACTIVE, 700, TEN_M, 4 * MIL) == 0,
          "five validators");
    CHECK(put_del(w, 0xD1, 0x22, 3 * MIL, 100) == 0 &&
          put_del(w, 0x55, 0x55, 4 * MIL, 200) == 0 &&
          put_del(w, 0x11, 0x11, 1 * MIL, 300) == 0, "three delegations");

    uint8_t fp11[64], fp22[64], fp33[64], fp44[64], fp55[64], fpD1[64];
    CHECK(fp_of(0x11, fp11) == 0 && fp_of(0x22, fp22) == 0 &&
          fp_of(0x33, fp33) == 0 && fp_of(0x44, fp44) == 0 &&
          fp_of(0x55, fp55) == 0 && fp_of(0xD1, fpD1) == 0, "fps");
    uint8_t v11[64], v22[64], v33[64], v44[64], v55[64];
    CHECK(vid_of(chain32, 0x11, v11) == 0 && vid_of(chain32, 0x22, v22) == 0
          && vid_of(chain32, 0x33, v33) == 0 &&
          vid_of(chain32, 0x44, v44) == 0 && vid_of(chain32, 0x55, v55) == 0,
          "validator_ids");

    /* three copy epochs, the econ writer's shape (kind 0 owner = the
     * validator; kind 1 owner = SHA3(dpk)); amounts differ per epoch so
     * "unchanged" is per row */
    const uint64_t ep[3] = { 0, E_LEN, 2 * E_LEN };
    for (int e = 0; e < 3; e++) {
        uint64_t k = (uint64_t)e + 1u;
        CHECK(put_copy(w, ep[e], fp11, fp11, 0, TEN_M + k) == 0 &&
              put_copy(w, ep[e], fp22, fp22, 0, TEN_M + 2 * k) == 0 &&
              put_copy(w, ep[e], fp33, fp33, 0, TEN_M + 3 * k) == 0 &&
              put_copy(w, ep[e], fp55, fp55, 0, TEN_M + 5 * k) == 0 &&
              put_copy(w, ep[e], fp22, fpD1, 1, 3 * MIL + k) == 0 &&
              put_copy(w, ep[e], fp55, fp55, 1, 4 * MIL + k) == 0 &&
              put_copy(w, ep[e], fp11, fp11, 1, 1 * MIL + k) == 0,
              "seven copy rows");
    }
    /* K4: Foundation sources 0x11 (7) and 0x33 (11) into an EXISTING
     * Foundation row (100); 0x22 and 0xD1 untouched */
    CHECK(put_acc(w, fp11, 7) == 0 && put_acc(w, fp33, 11) == 0 &&
          put_acc(w, F, 100) == 0 && put_acc(w, fp22, 5) == 0 &&
          put_acc(w, fpD1, 13) == 0, "accruals");

    sqlite3_int64 sup0 = -1, acc0 = -1, copy0 = -1;
    CHECK(staked(w, &sup0) == 0 &&
          count_q(w, "SELECT SUM(amount) FROM v2_reward_accrual", &acc0)
              == 0 &&
          count_q(w, "SELECT COUNT(*) FROM v2_balance_copy", &copy0) == 0,
          "pre-migration sums");
    CHECK((uint64_t)sup0 == 4 * TEN_M + 8 * MIL, "48M staked before");

    CHECK(migrate_tx(w, H, chain32, F) == 0, "the migration commits");

    /* validators + roles */
    CHECK(chk_val(w, chain32, 0x11, F, DNAC_VALIDATOR_ACTIVE, TWO_M,
                  1 * MIL + EIGHT_M) == 0, "0x11: Foundation, 2M, 1M+8M");
    CHECK(chk_val(w, chain32, 0x22, fp22, DNAC_VALIDATOR_ELIGIBLE, TWO_M,
                  3 * MIL + EIGHT_M) == 0, "0x22: own owner, 2M, 3M+8M");
    CHECK(chk_val(w, chain32, 0x33, F, DNAC_VALIDATOR_RETIRING, TEN_M, 0)
              == 0, "0x33: Foundation, RETIRING amounts untouched");
    CHECK(chk_val(w, chain32, 0x44, fp44, DNAC_VALIDATOR_UNSTAKED, 0, 0)
              == 0, "0x44: own owner, UNSTAKED zero untouched");
    CHECK(chk_val(w, chain32, 0x55, fp55, DNAC_VALIDATOR_ACTIVE, TWO_M,
                  4 * MIL + EIGHT_M) == 0, "0x55: own owner, 2M, 4M+8M");
    {
        sqlite3_int64 n = -1;
        CHECK(count_q(w, "SELECT COUNT(*) FROM v2_validator_roles", &n) == 0
              && n == 5, "five roles rows");
        CHECK(count_q(w, "SELECT COUNT(*) FROM validators", &n) == 0 &&
              n == 5, "five validators rows");
    }

    /* delegations */
    CHECK(chk_del(w, fpD1, v22, 3 * MIL, 100) == 0,
          "0xD1 -> 0x22 re-keyed, amount and height kept");
    CHECK(chk_del(w, fp55, v55, 4 * MIL + EIGHT_M, 200) == 0,
          "0x55 node-key self-delegation TOPPED UP, height unchanged");
    CHECK(chk_del(w, fp11, v11, 1 * MIL, 300) == 0,
          "0x11 node-key self-delegation kept as it was (owner is the "
          "Foundation, D5)");
    CHECK(chk_del(w, F, v11, EIGHT_M, H) == 0,
          "0x11 Foundation self-delegation: a NEW row at H");
    CHECK(chk_del(w, fp22, v22, EIGHT_M, H) == 0,
          "0x22 self-delegation: a NEW row at H");
    {
        sqlite3_int64 n = -1;
        nodus_v2_delegation_row_t d;
        CHECK(count_q(w, "SELECT COUNT(*) FROM delegations", &n) == 0 &&
              n == 5, "five delegation rows");
        CHECK(nodus_delegation_v2_get(w, F, v33, &d) == 1,
              "no self-delegation for the RETIRING row");
        CHECK(nodus_delegation_v2_get(w, fp44, v44, &d) == 1,
              "no self-delegation for the UNSTAKED row");
    }
    {
        uint8_t *dpk = malloc(PKLEN), *vpk = malloc(PKLEN);
        uint8_t *pk = malloc(PKLEN), *zero = calloc(1, PKLEN);
        CHECK(dpk && vpk && pk && zero, "alloc");
        int ok;
        pk_of(0x11, pk);
        ok = get_del_pks(w, F, v11, dpk, vpk) == 0 &&
             memcmp(dpk, zero, PKLEN) == 0 && memcmp(vpk, pk, PKLEN) == 0;
        pk_of(0x22, pk);
        ok = ok && get_del_pks(w, fp22, v22, dpk, vpk) == 0 &&
             memcmp(dpk, pk, PKLEN) == 0 && memcmp(vpk, pk, PKLEN) == 0;
        free(dpk); free(vpk); free(pk); free(zero);
        CHECK(ok, "new rows: 2592-byte pubkeys (Foundation delegator 2592 x "
              "0x00; own owner = its key)");
    }

    /* supply */
    {
        sqlite3_int64 sup1 = -1, dsum = -1, tsum = -1;
        CHECK(staked(w, &sup1) == 0 && sup1 == sup0,
              "Σself + Σtotal_delegated unchanged");
        CHECK(count_q(w, "SELECT SUM(amount) FROM delegations", &dsum) == 0 &&
              count_q(w, "SELECT SUM(total_delegated) FROM validators",
                      &tsum) == 0 && dsum == tsum,
              "Σdelegations == Σtotal_delegated");
    }

    /* balance copies: every epoch re-keyed, amounts equal */
    for (int e = 0; e < 3; e++) {
        uint64_t k = (uint64_t)e + 1u, a = 0;
        CHECK(get_copy(w, ep[e], v11, v11, 0, &a) == 0 && a == TEN_M + k,
              "kind 0 of 0x11 re-keyed, amount equal");
        CHECK(get_copy(w, ep[e], v22, v22, 0, &a) == 0 &&
              a == TEN_M + 2 * k, "kind 0 of 0x22");
        CHECK(get_copy(w, ep[e], v33, v33, 0, &a) == 0 &&
              a == TEN_M + 3 * k, "kind 0 of 0x33");
        CHECK(get_copy(w, ep[e], v55, v55, 0, &a) == 0 &&
              a == TEN_M + 5 * k, "kind 0 of 0x55");
        CHECK(get_copy(w, ep[e], v22, fpD1, 1, &a) == 0 &&
              a == 3 * MIL + k, "kind 1 0xD1 -> 0x22, owner kept");
        CHECK(get_copy(w, ep[e], v55, fp55, 1, &a) == 0 &&
              a == 4 * MIL + k, "kind 1 0x55 -> 0x55, owner kept");
        CHECK(get_copy(w, ep[e], v11, fp11, 1, &a) == 0 &&
              a == 1 * MIL + k, "kind 1 0x11 -> 0x11, owner kept");
        CHECK(get_copy(w, ep[e], fp11, fp11, 0, &a) == 1,
              "the old key is gone");
    }
    {
        sqlite3_int64 n = -1;
        CHECK(count_q(w, "SELECT COUNT(*) FROM v2_balance_copy", &n) == 0 &&
              n == copy0 && n == 21, "21 copy rows before and after");
    }

    /* K4 */
    {
        uint64_t a = 0;
        sqlite3_int64 acc1 = -1;
        CHECK(get_acc(w, F, &a) == 0 && a == 100 + 7 + 11,
              "Foundation accrual = 100 + 7 + 11 (checked add)");
        CHECK(get_acc(w, fp11, &a) == 1 && get_acc(w, fp33, &a) == 1,
              "the Foundation nodes' source rows are deleted");
        CHECK(get_acc(w, fp22, &a) == 0 && a == 5 &&
              get_acc(w, fpD1, &a) == 0 && a == 13,
              "every other accrual untouched");
        CHECK(count_q(w, "SELECT SUM(amount) FROM v2_reward_accrual", &acc1)
                  == 0 && acc1 == acc0, "Σaccrual unchanged");
    }
    fx_close(&fx);
    return 0;
}

/* A2 — K4 without a Foundation row; a second run and autocommit refused */
static int t_direct_no_target_and_rerun(void) {
    fixture_t fx;
    uint8_t chain32[32], F[64], fp11[64], d0[64], d1[64];
    uint64_t a = 0;
    memset(chain32, 0x5B, sizeof(chain32));
    memset(F, 0xC4, sizeof(F));
    CHECK(fxd_open(&fx, "a2") == 0, "fixture DB");
    CHECK(put_val(fx.w, 0x11, DNAC_VALIDATOR_ACTIVE, 0, TEN_M, 0) == 0,
          "one genesis validator (active_since 0 <= 1: Foundation)");
    CHECK(fp_of(0x11, fp11) == 0 && put_acc(fx.w, fp11, 9) == 0,
          "its accrual 9, no Foundation row");

    CHECK(v2x_db_digest(fx.w, d0) == 0, "digest");
    CHECK(nodus_witness_v2_roles_migrate(fx.w, 5, chain32, F) == -2,
          "autocommit mode: fault");
    CHECK(v2x_db_digest(fx.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
          "nothing written");

    CHECK(migrate_tx(fx.w, 5, chain32, F) == 0, "the migration commits");
    CHECK(get_acc(fx.w, F, &a) == 0 && a == 9, "Foundation row created: 9");
    CHECK(get_acc(fx.w, fp11, &a) == 1, "source deleted");

    CHECK(v2x_db_digest(fx.w, d0) == 0, "digest after");
    CHECK(migrate_tx(fx.w, 5, chain32, F) == -2,
          "a second migration on the migrated DB is a fault");
    CHECK(v2x_db_digest(fx.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
          "and changes nothing");
    fx_close(&fx);
    return 0;
}

/* A3 — each fault leaves the DB unchanged once the transaction rolls back */
static int fault_case(const char *tag, int which) {
    fixture_t fx;
    uint8_t chain32[32], F[64], d0[64], d1[64];
    memset(chain32, 0x5C, sizeof(chain32));
    memset(F, 0xC5, sizeof(F));
    CHECK(fxd_open(&fx, tag) == 0, "fixture DB");
    CHECK(put_val(fx.w, 0x11, DNAC_VALIDATOR_ACTIVE, 1, TEN_M, 0) == 0,
          "a well-formed validator");
    if (which == 0) {
        CHECK(put_val(fx.w, 0x22, DNAC_VALIDATOR_ACTIVE, 50, 9 * MIL, 0)
                  == 0, "a bonded row holding 9M");
    } else if (which == 1) {
        uint8_t fp99[64], fp11[64];
        CHECK(fp_of(0x99, fp99) == 0 && fp_of(0x11, fp11) == 0 &&
              put_copy(fx.w, 0, fp11, fp11, 0, TEN_M) == 0 &&
              put_copy(fx.w, E_LEN, fp99, fp99, 0, TEN_M) == 0,
              "a copy row naming no validator");
    } else {
        CHECK(put_del(fx.w, 0xD1, 0x99, MIL, 10) == 0,
              "a delegation to a pubkey with no validator row");
    }
    CHECK(v2x_db_digest(fx.w, d0) == 0, "digest before");
    CHECK(migrate_tx(fx.w, 77, chain32, F) == -2, "a node FAULT (-2)");
    CHECK(v2x_db_digest(fx.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
          "the DB is unchanged after the rollback");
    fx_close(&fx);
    return 0;
}

static int t_direct_faults(void) {
    if (fault_case("bond9m", 0) != 0) return 1;
    if (fault_case("unmapped", 1) != 0) return 1;
    if (fault_case("delnov", 2) != 0) return 1;
    return 0;
}

/* ══ B. the engine — the gen-4 edge on the seeded fixture ══════════ */

#define H9   3u
#define HE   5u
#define HS   8u      /* param 16 effective: the edge runs in block HS-1 */

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

/* test_hf4_switch fx_open_storage's shape: HF-2 on from 1, param 9 at
 * H9, param 14 at HE, param 16 at HS — all before the engine genesis */
static int fxe_open(fixture_t *fx, const char *tag) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_hf6_migrate_%s_XXXXXX",
             tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain16, 0x34, sizeof(fx->chain16));
    if (v2x_seed_prepare(fx->w, fx->chain16, 0) != 0) return -1;
    if (cc_row(fx->w, DNAC_CFG_HF2_ACTIVE, DNAC_CFG_HF2_ACTIVE_ON, 1, 11)
        != 0 ||
        cc_row(fx->w, DNAC_CFG_RULESET_GEN2,
               (uint64_t)DNAC_CFG_RULESET_GEN2_D2, H9, 12) != 0 ||
        cc_row(fx->w, DNAC_CFG_EVM_ACTIVE, (uint64_t)DNAC_CFG_EVM_ACTIVE_D,
               HE, 14) != 0 ||
        cc_row(fx->w, DNAC_CFG_RULESET_GEN_STORAGE,
               (uint64_t)DNAC_CFG_RULESET_GEN_STORAGE_D, HS, 13) != 0)
        return -1;
    return v2x_seed_genesis(fx->w, fx->chain16, 0, NULL, 0, NULL);
}

static void mk_block(nodus_v2_block_t *b, uint64_t h) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = nodus_v2_epoch_for_height(h);
    b->envs = NULL;
    b->n_envs = 0;
}

static int run_to(fixture_t *fx, uint64_t last) {
    nodus_v2_block_t b;
    for (uint64_t h = 1; h <= last; h++) {
        mk_block(&b, h);
        if (v2x_cmt_apply_ok(fx->w, &b) != 0) return -1;
    }
    return 0;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static int t_engine_edge(void) {
    fixture_t fx;
    nodus_v2_block_t b;
    const nodus_domain_runtime_t *g4s =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *g4c =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_CORE);
    CHECK(g4s && g4c, "generation 4 is compiled");
    CHECK(E_LEN > HS, "no epoch boundary among heights 1..HS");

#ifdef DNAC_HF6_FOUNDATION_OWNER_IS_DEFAULT
    {
        static const char k8[] =
            "8eff7f418ab7a4432118ff99e21f2c3d1baf186200c148a3bba7d274499386ac"
            "970e267a9c9b3bbc05bfff1c62a72d63f72a555db780feeaaad4fb49ba9f7b89";
        uint8_t want[64];
        int ok = sizeof(k8) == 129;
        for (int i = 0; ok && i < 64; i++) {
            int hi = hexval(k8[2 * i]), lo = hexval(k8[2 * i + 1]);
            if (hi < 0 || lo < 0) ok = 0;
            else want[i] = (uint8_t)(hi * 16 + lo);
        }
        CHECK(ok && memcmp(want, k_found_compiled, 64) == 0,
              "the compiled Foundation owner IS the K8 address");
    }
#else
    (void)hexval;
#endif

    CHECK(fxe_open(&fx, "edge") == 0, "seeded chain (param 16 at HS)");
    CHECK(run_to(&fx, HS - 2u) == 0, "idle blocks 1..HS-2");
    sqlite3_int64 n = -1, sup0 = -1, copy0 = -1;
    CHECK(count_q(fx.w, "SELECT COUNT(*) FROM v2_validator_roles", &n) == 0
          && n == 0, "no roles row before the edge");
    CHECK(staked(fx.w, &sup0) == 0 &&
          count_q(fx.w, "SELECT COUNT(*) FROM v2_balance_copy", &copy0) == 0,
          "pre-edge sums");

    /* the genesis validators and the chain id the phase reads */
    uint8_t chain32[DNA_CHAIN_ID_LEN];
    CHECK(nodus_witness_v2_chain_id(fx.w, chain32) == 0, "chain id");
    enum { NV_MAX = 16 };
    uint8_t *pks = malloc((size_t)NV_MAX * PKLEN);
    size_t nv = 0;
    CHECK(pks != NULL, "alloc");
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db, "SELECT pubkey, status, "
                                 "active_since_block, self_stake FROM "
                                 "validators ORDER BY pubkey ASC", -1, &st,
                                 NULL) == SQLITE_OK, "prepare");
        int ok = 1;
        while (sqlite3_step(st) == SQLITE_ROW) {
            if (nv == NV_MAX ||
                sqlite3_column_bytes(st, 0) != PKLEN ||
                sqlite3_column_int64(st, 1) != DNAC_VALIDATOR_ACTIVE ||
                sqlite3_column_int64(st, 2) > 1 ||
                (uint64_t)sqlite3_column_int64(st, 3) != TEN_M) {
                ok = 0;
                break;
            }
            memcpy(pks + nv * PKLEN, sqlite3_column_blob(st, 0), PKLEN);
            nv++;
        }
        sqlite3_finalize(st);
        CHECK(ok && nv == 7, "seven ACTIVE genesis rows, since <= 1, 10M");
    }

    /* block HS-1: the gen-4 edge */
    mk_block(&b, HS - 1u);
    CHECK(v2x_cmt_apply_ok(fx.w, &b) == 0, "the H-1 block commits");
    {
        const nodus_domain_runtime_t *rs = NULL, *rc = NULL;
        CHECK(nodus_witness_v2_runtime_for(fx.w, DNA_DOMAIN_SYSTEM, 1, &rs)
                  == 0 && rs == g4s, "SYSTEM resolves generation 4");
        CHECK(nodus_witness_v2_runtime_for(fx.w, DNA_DOMAIN_CORE, 1, &rc)
                  == 0 && rc == g4c, "CORE resolves generation 4");
    }
    CHECK(count_q(fx.w, "SELECT COUNT(*) FROM v2_validator_roles", &n) == 0
          && n == 7, "seven roles rows");
    CHECK(count_q(fx.w, "SELECT COUNT(*) FROM delegations", &n) == 0 &&
          n == 7, "seven self-delegations");
    for (size_t i = 0; i < nv; i++) {
        nodus_v2_validator_row_t *r = calloc(1, sizeof(*r));
        uint8_t vid[64];
        uint64_t a = 0;
        int ok = r != NULL &&
            dna_validator_id_migrated(vid, chain32, pks + i * PKLEN) == 0 &&
            nodus_validator_v2_get(fx.w, vid, r) == 0 &&
            memcmp(r->owner_fp, k_found_compiled, 64) == 0 &&
            r->rec.self_stake == TWO_M &&
            r->rec.total_delegated == EIGHT_M &&
            r->rec.external_delegated == EIGHT_M &&
            chk_del(fx.w, k_found_compiled, vid, EIGHT_M, HS) == 0 &&
            get_copy(fx.w, 0, vid, vid, 0, &a) == 0 && a == TEN_M;
        free(r);
        CHECK(ok, "row i: Foundation owner, 2M + 8M at H, copy(0) re-keyed "
              "with 10M");
    }
    free(pks);
    {
        sqlite3_int64 sup1 = -1, copy1 = -1;
        CHECK(staked(fx.w, &sup1) == 0 && sup1 == sup0,
              "staked supply unchanged across the edge");
        CHECK(count_q(fx.w, "SELECT COUNT(*) FROM v2_balance_copy", &copy1)
                  == 0 && copy1 == copy0, "copy row count unchanged");
    }
    {
        uint8_t committed[64], fresh[64];
        CHECK(nodus_witness_v2_committed_global_root(fx.w, committed) == 0 &&
              nodus_witness_global_root_v2(fx.w, fresh, NULL, NULL, NULL)
                  == 0 && memcmp(committed, fresh, 64) == 0,
              "committed H-1 global root == recomputation");
    }

    /* block HS: generation 4, no second migration */
    {
        uint8_t r0[64], r1[64];
        CHECK(nodus_witness_domreg_root(fx.w, r0) == 0, "registry root");
        mk_block(&b, HS);
        CHECK(v2x_cmt_apply_ok(fx.w, &b) == 0,
              "the idle H block applies under generation 4");
        CHECK(nodus_witness_domreg_root(fx.w, r1) == 0 &&
              memcmp(r0, r1, 64) == 0, "no second switch");
        CHECK(count_q(fx.w, "SELECT COUNT(*) FROM v2_validator_roles", &n)
                  == 0 && n == 7, "no second migration");
    }
    fx_close(&fx);
    return 0;
}

static int t_engine_replay(void) {
    fixture_t a, b2;
    nodus_v2_block_t b;
    uint8_t da[64], db[64];
    CHECK(fxe_open(&a, "repA") == 0 && fxe_open(&b2, "repB") == 0,
          "twin seeded chains");
    CHECK(run_to(&a, HS - 2u) == 0 && run_to(&b2, HS - 2u) == 0,
          "both at HS-2");

    /* A: a stray roles row makes the migration fault inside H-1 */
    CHECK(run_sql(a.w->db, "INSERT INTO v2_validator_roles (validator_id, "
                  "owner_fp, pending_consensus_pubkey, "
                  "consensus_key_effective_epoch) VALUES (zeroblob(64), "
                  "zeroblob(64), zeroblob(2592), 0)") == 0, "stray row");
    mk_block(&b, HS - 1u);
    CHECK(v2x_cmt_fault_why(a.w, &b, V2X_FAULT,
                            "generation-4 validator migration failed") == 0,
          "the faulted edge: node FAULT, DB byte-unchanged (registry "
          "switch rolled back with it)");
    CHECK(run_sql(a.w->db, "DELETE FROM v2_validator_roles") == 0,
          "stray row removed");
    mk_block(&b, HS - 1u);
    CHECK(v2x_cmt_apply_ok(a.w, &b) == 0, "the replay commits");

    /* B: H-1 once */
    mk_block(&b, HS - 1u);
    CHECK(v2x_cmt_apply_ok(b2.w, &b) == 0, "the twin commits once");

    CHECK(v2x_db_digest(a.w, da) == 0 && v2x_db_digest(b2.w, db) == 0 &&
          memcmp(da, db, 64) == 0,
          "replay after the failed attempt == a single clean apply");
    fx_close(&a);
    fx_close(&b2);
    return 0;
}

int main(void) {
    static const struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        { "direct_expected_rows",      t_direct_expected },
        { "direct_no_target_rerun",    t_direct_no_target_and_rerun },
        { "direct_faults",             t_direct_faults },
        { "engine_gen4_edge",          t_engine_edge },
        { "engine_replay_after_fault", t_engine_replay },
    };
    size_t failed = 0, n = sizeof(cases) / sizeof(cases[0]);
    for (size_t i = 0; i < n; i++) {
        int rc = cases[i].fn();
        fprintf(stderr, "[%s] %s\n", rc == 0 ? "PASS" : "FAIL",
                cases[i].name);
        if (rc != 0) failed++;
    }
    fprintf(stderr, "test_hf6_migrate: %zu/%zu cases passed, %d checks\n",
            n - failed, n, g_checks);
    return failed == 0 ? 0 : 1;
}
