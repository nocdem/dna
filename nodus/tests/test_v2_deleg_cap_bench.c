/**
 * Nodus — tokenomics-v3 P3-6: the 2048-delegator cap, MEASURED.
 *
 * Governing records: decision file docs/plans/decisions/2026-09-22-nodus-
 * tokenomics-v3-operator.md §1 "Validator başına delegator hedefi,
 * uygulanabilir olması koşuluyla 2048 olacak" (2048 per validator, IF it
 * is feasible) and design docs/plans/2026-09-23-tokenomics-v3-consensus-
 * binding-design.md §8 P3-6 ("uygulanabilirlik ÖLÇÜLÜR" — feasibility is
 * MEASURED; the threshold is the operator's, against the 4 s
 * timeout_commit).
 *
 * WHAT IT MEASURES (wall time, CLOCK_MONOTONIC, printed — NEVER asserted):
 *   (1) ONE epoch boundary at E = DNAC_EPOCH_LENGTH (720 in a default
 *       build) with 32 seated validators × 2048 delegators each (65 536
 *       delegation rows) plus one graduating validator holding another
 *       2048 — the whole nodus_witness_v2_epoch_boundary_apply call, and
 *       inside it, through the boundary's own stage callback (every stage
 *       returns 0, so it only timestamps):
 *         - the reward distribution over the 32 × 2048 source copy,
 *         - the graduation's auto-release of 2048 delegations (P3-4),
 *         - Rule N, the next-snapshot build ("okuma B" over the frozen
 *           copy, P3-1),
 *         - the balance-copy write (65 568 rows) + prune;
 *   (2) ONE payday over the 65 568 accrual rows that boundary credited
 *       (32 validators + 65 536 delegators);
 *   (3) the engine genesis that writes copy(0) over the seeded rows, as
 *       context (it is one-time, not a per-boundary cost).
 *
 * WHAT IT ASSERTS (correctness only): the boundary commits and fires
 * with exactly one graduate; the graduate's 2048 delegations are released
 * as 2048 locked UTXOs and deleted, its delegated totals zeroed; copy(E)
 * holds exactly 32 + 32 × 2048 rows; every one of the 65 568 recipients
 * accrued (a nonzero share, hand-derived below); the payday pays every
 * row and empties the table; the CORE supply equation closes after each
 * step. No assertion depends on a timing.
 *
 * Hand derivation of "every recipient accrues": POOL = 2^16 × 10^12, so
 * payout = POOL >> 16 = 10^12; 32 equal members → share = 3.125 × 10^10
 * each; total_stake = 10^15 + 2048 × 10^10 = 1.02048 × 10^15, so base =
 * floor(share × 10^15 / total) ≈ 3.0623 × 10^10, gross ≈ 6.27 × 10^8,
 * commission 10 % ≈ 6.27 × 10^7, net ≈ 5.64 × 10^8, and each of the 2048
 * equal delegators gets floor(net / 2048) ≈ 2.75 × 10^5 > 0.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * Compile flags: none beyond a default build. Environment: none. Runtime:
 * the fixture writes ~67 600 delegation rows (two SHA3-512 of a 2592-byte
 * key each) and one boundary; expect tens of seconds, dominated by the
 * genesis root over the delegation leaves and the payday.
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * One /tmp/test_v2_capbench_XXXXXX directory, removed at close (left
 * behind if a CHECK aborts).
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. The boundary is applied DIRECTLY (nodus_witness_v2_epoch_boundary_
 *     apply inside a transaction this test owns), not through a driven
 *     block: driving 720 blocks would recompute the domain roots over
 *     ~67 600 delegation leaves at every height, which is the block
 *     engine's cost, not the boundary's. So the numbers EXCLUDE the
 *     per-block root recomputation a real boundary block also pays (the
 *     SYSTEM root over every delegation leaf, the CORE root over every
 *     UTXO and accrual row). That cost exists on every block of a chain
 *     this full, boundary or not, and is NOT measured here. Because no
 *     block is driven, the successor committee seed's inputs at E − 1
 *     (the Comet block-store records 1 … E − 1 and one v2_blocks row)
 *     are PLANTED — identity rows only, out of every root; the chain is
 *     a seeded version-3 genesis (tokenomics-v3 P4).
 *  2. Attendance is written straight into v2_attendance (every member
 *     signed every block of the epoch), so the distribution pays every
 *     member — the worst (most work) case, not a typical one.
 *  3. One machine, one run: the numbers are an order of magnitude, not a
 *     bound.
 *
 * Copyright (c) 2026 nocdem — SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_econ.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_delegation.h"
#include "witness/nodus_witness_vset.h"
#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_types.h"
#include "dnac/dnac.h"
#include "dnac/ledger_ids.h"
#include "dnac/validator.h"
#include "crypto/hash/qgp_sha3.h"

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "v2_genesis_fixture.h"

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", \
                __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

#define E        ((uint64_t)DNAC_EPOCH_LENGTH)
#define N_VAL    32                               /* seated validators   */
#define N_DEL    NODUS_MAX_DELEGATORS_PER_VALIDATOR /* per validator      */
#define GRAD     N_VAL                            /* index of the 33rd,
                                                   * graduating validator */
#define BOND     DNAC_SELF_STAKE_AMOUNT
#define DAMT     ((uint64_t)DNAC_MIN_DELEGATION)
#define UTXO_A   5000000ULL
#define POOL     (65536ULL * 1000000000000ULL)    /* payout = 10^12      */
#define COMM     1000u                            /* 10 %                */

_Static_assert(N_DEL == 2048, "the P3-6 cap this bench measures");

/* ── deterministic pseudo-keys: no signature is ever made or checked ─── */
static void val_pk(int v, uint8_t out[DNAC_PUBKEY_SIZE]) {
    for (int b = 0; b < DNAC_PUBKEY_SIZE; b++)
        out[b] = (uint8_t)((b * 31u + (unsigned)v * 7u + 11u) & 0xFF);
    out[0] = 0xA0;
    out[1] = (uint8_t)v;
}

static void del_pk(int v, int d, uint8_t out[DNAC_PUBKEY_SIZE]) {
    for (int b = 0; b < DNAC_PUBKEY_SIZE; b++)
        out[b] = (uint8_t)((b * 13u + (unsigned)d * 5u + 3u) & 0xFF);
    out[0] = 0xD0;
    out[1] = (uint8_t)v;
    out[2] = (uint8_t)(d >> 8);
    out[3] = (uint8_t)d;
}

static void fp_hex(const uint8_t pk[DNAC_PUBKEY_SIZE], char out[129]) {
    static const char hexd[] = "0123456789abcdef";
    uint8_t full[64];
    qgp_sha3_512(pk, DNAC_PUBKEY_SIZE, full);
    for (int b = 0; b < 64; b++) {
        out[2 * b]     = hexd[full[b] >> 4];
        out[2 * b + 1] = hexd[full[b] & 0xF];
    }
    out[128] = '\0';
}

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1.0e6;
}

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

static int run_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL failed: %s\n", err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static int64_t q1(nodus_witness_t *w, const char *sql) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    int64_t v = -1;
    if (sqlite3_step(st) == SQLITE_ROW) v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

/* ── the stage-timestamp callback (returns 0: never interrupts) ──────── */
#define N_STAGES 32
static double g_stage_ms[N_STAGES];
static int stage_cb(void *ud, nodus_v2_epoch_stage_t s, uint32_t idx) {
    (void)ud; (void)idx;
    if ((int)s >= 0 && (int)s < N_STAGES) g_stage_ms[(int)s] = now_ms();
    return 0;
}

int main(void) {
    printf("=== tokenomics-v3 P3-6 — 2048-delegator cap, measured "
           "(E = %llu) ===\n", (unsigned long long)E);

    nodus_witness_t *w = calloc(1, sizeof(*w));
    CHECK(w != NULL, "alloc");
    w->cached_committee_epoch_start = UINT64_MAX;
    char dir[128];
    snprintf(dir, sizeof(dir), "/tmp/test_v2_capbench_XXXXXX");
    CHECK(mkdtemp(dir) != NULL, "mkdtemp");
    snprintf(w->data_path, sizeof(w->data_path), "%s", dir);
    uint8_t cid16[16];
    memset(cid16, 0x4E, sizeof(cid16));
    /* tokenomics-v3 P4: a SEEDED VERSION-3 GENESIS (v2_genesis_fixture.h)
     * — v2x_seed_prepare here, the test's rows, v2x_seed_genesis below */
    CHECK(v2x_seed_prepare(w, cid16, 0) == 0, "pre-genesis chain db");

    /* ── stage 1: 32 ACTIVE + 1 RETIRING validators, 33 × 2048
     *    delegations, the supply row with the reward reserve ─────────── */
    const double t_seed0 = now_ms();
    CHECK(run_sql(w->db, "BEGIN IMMEDIATE") == 0, "begin seed");
    static uint8_t pk[DNAC_PUBKEY_SIZE];
    for (int v = 0; v <= GRAD; v++) {
        dnac_validator_record_t r;
        memset(&r, 0, sizeof(r));
        val_pk(v, r.pubkey);
        r.self_stake = BOND;
        r.total_delegated = r.external_delegated = (uint64_t)N_DEL * DAMT;
        r.commission_bps = COMM;
        /* the graduate is RETIRING BEFORE the genesis snapshots freeze, so
         * it is in neither snapshot(0) nor snapshot(E) and graduates at E
         * (the test_v2_epoch.c §2e pattern) */
        r.status = (v == GRAD) ? (uint8_t)DNAC_VALIDATOR_RETIRING
                               : (uint8_t)DNAC_VALIDATOR_ACTIVE;
        r.active_since_block = 1;
        fp_hex(r.pubkey, (char *)r.unstake_destination_fp);
        CHECK(nodus_validator_insert(w, &r) == 0, "validator");
        for (int d = 0; d < N_DEL; d++) {
            dnac_delegation_record_t dr;
            memset(&dr, 0, sizeof(dr));
            del_pk(v, d, dr.delegator_pubkey);
            memcpy(dr.validator_pubkey, r.pubkey, DNAC_PUBKEY_SIZE);
            dr.amount = DAMT;
            CHECK(nodus_delegation_insert(w, &dr) == 0, "delegation");
        }
    }
    {
        char sql[128];
        snprintf(sql, sizeof(sql), "UPDATE validator_stats SET value = %d "
                 "WHERE key = 'active_count'", N_VAL + 1);
        CHECK(run_sql(w->db, sql) == 0, "active_count");
    }
    {
        const uint64_t n_rows = (uint64_t)(N_VAL + 1);
        const uint64_t supply = UTXO_A + n_rows * BOND +
                                n_rows * (uint64_t)N_DEL * DAMT + POOL;
        char sql[400];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO supply_tracking (id, genesis_supply, "
                 "total_burned, total_minted, current_supply, last_tx_hash, "
                 "last_sequence, reward_pool) VALUES (1, %llu, 0, 0, %llu, "
                 "zeroblob(64), 0, %llu)",
                 (unsigned long long)supply, (unsigned long long)supply,
                 (unsigned long long)POOL);
        CHECK(run_sql(w->db, sql) == 0, "supply");
        char fp[129];
        val_pk(0, pk);
        fp_hex(pk, fp);
        uint8_t seed[32], nul[64], pre[160];
        memset(seed, 0xA1, sizeof(seed));
        memcpy(pre, fp, 128);
        memcpy(pre + 128, seed, 32);
        CHECK(qgp_sha3_512(pre, sizeof(pre), nul) == 0, "nul");
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(w->db,
                  "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
                  "tx_hash, output_index, block_height, created_at, "
                  "unlock_block, domain_id) VALUES (?1, ?2, ?3, zeroblob(64), "
                  "zeroblob(64), 0, 0, 0, 0, 1)", -1, &st, NULL) == SQLITE_OK,
              "prep utxo");
        sqlite3_bind_blob(st, 1, nul, 64, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, fp, 128, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)UTXO_A);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "utxo");
        sqlite3_finalize(st);
    }
    CHECK(run_sql(w->db, "COMMIT") == 0, "commit seed");
    CHECK(nodus_witness_vset_commit_genesis(w, 1) == 0, "genesis snapshots");
    const double t_seed1 = now_ms();

    /* ── stage 2: the engine genesis (writes copy(0)) — the seeded
     *    version-3 genesis: registry, nodus_witness_v2_genesis_cmt, the
     *    stored document, the reopen through the production open path ─ */
    uint8_t chain_id[DNA_CHAIN_ID_LEN];
    const double t_gen0 = now_ms();
    /* not a real genesis: a spendable UTXO_A row (fee funding) and a
     * RETIRING graduate — the boundary under measurement — which a
     * version-3 genesis (every row ACTIVE, no UTXOs) cannot write */
    v2x_seed_not_real(V2X_SEED_NOT_REAL_UTXOS | V2X_SEED_NOT_REAL_STATUSES);
    CHECK(v2x_seed_genesis(w, cid16, 0, NULL, 0, NULL) == 0, "v3 genesis");
    const double t_gen1 = now_ms();
    CHECK(nodus_witness_v2_chain_id(w, chain_id) == 0, "chain id");
    CHECK(q1(w, "SELECT COUNT(*) FROM v2_balance_copy WHERE epoch_start = 0")
              == (int64_t)(N_VAL + 1) * (1 + N_DEL),
          "copy(0): 33 bonds + 33 × 2048 delegations");

    /* ── the boundary's inputs the bench must plant, because it applies
     *    the boundary directly instead of driving E − 1 blocks:
     *    (a) the successor committee seed commit_next(E) reads at the
     *        lookback height E − 1 (committee.c v2_seed_block_id): the
     *        Comet block-store record there — the store keeps heights
     *        contiguous, so records 1 … E − 1 are written, exactly the
     *        ones the fixture host (v2x_cmt_apply) writes per block —
     *        and the v2_blocks row at E − 1 whose block_id is that
     *        record's hash (v2_blocks is out of every root);
     *    (b) a full-epoch attendance row per seated member (also out of
     *        every root). ─────────────────────────────────────────────── */
    {
        sqlite3_stmt *st = NULL;
        uint8_t hash[64], nvh[64], prop[32];
        uint64_t secs = 0;
        CHECK(run_sql(w->db, "BEGIN IMMEDIATE") == 0, "begin lookback");
        for (uint64_t h = 1; h <= E - 1; h++)
            CHECK(v2x_cmt_store_block(w, h, hash, nvh, prop, &secs) == 0,
                  "block-store record");
        CHECK(sqlite3_prepare_v2(w->db,
                  "INSERT INTO v2_blocks (global_height, block_id, "
                  "prev_block_id, epoch, tx_root, domain_updates_root, "
                  "domains_root, global_root, vset_hash, tx_count) VALUES "
                  "(?1, ?2, zeroblob(64), 0, zeroblob(64), zeroblob(64), "
                  "zeroblob(64), zeroblob(64), zeroblob(64), 0)",
                  -1, &st, NULL) == SQLITE_OK, "prep v2_blocks");
        sqlite3_bind_int64(st, 1, (sqlite3_int64)(E - 1));
        sqlite3_bind_blob(st, 2, hash, 64, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "lookback v2_blocks row");
        sqlite3_finalize(st);
        CHECK(run_sql(w->db, "COMMIT") == 0, "commit lookback");
        for (int v = 0; v < N_VAL; v++) {
            uint8_t full[64];
            val_pk(v, pk);
            CHECK(qgp_sha3_512(pk, DNAC_PUBKEY_SIZE, full) == 0, "voter id");
            st = NULL;
            CHECK(sqlite3_prepare_v2(w->db,
                      "INSERT INTO v2_attendance (voter_id, signed_count, "
                      "last_signed_height) VALUES (?1, ?2, ?3)",
                      -1, &st, NULL) == SQLITE_OK, "prep att");
            sqlite3_bind_blob(st, 1, full, 32, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 2, (sqlite3_int64)E);
            sqlite3_bind_int64(st, 3, (sqlite3_int64)(E - 1));
            CHECK(sqlite3_step(st) == SQLITE_DONE, "attendance");
            sqlite3_finalize(st);
        }
    }

    /* ── (1) THE BOUNDARY ─────────────────────────────────────────────── */
    for (int i = 0; i < N_STAGES; i++) g_stage_ms[i] = 0.0;
    nodus_v2_epoch_result_t out;
    CHECK(run_sql(w->db, "BEGIN IMMEDIATE") == 0, "begin boundary");
    const double t_b0 = now_ms();
    const int brc = nodus_witness_v2_epoch_boundary_apply(w, E, chain_id,
                                                          stage_cb, NULL,
                                                          &out);
    const double t_b1 = now_ms();
    CHECK(brc == 0, "the boundary applies");
    CHECK(run_sql(w->db, "COMMIT") == 0, "commit boundary");
    CHECK(out.fired == 1 && out.n_graduates == 1 && out.dist_accrued > 0,
          "fired, one graduate, a paying distribution");
    CHECK(q1(w, "SELECT COUNT(*) FROM utxo_set WHERE output_index >= "
                "2147483648") == N_DEL,
          "the graduate's 2048 delegations released as 2048 UTXOs");
    CHECK(q1(w, "SELECT COUNT(*) FROM delegations") ==
              (int64_t)N_VAL * N_DEL,
          "the graduate's delegation rows are gone, every other stays");
    {
        dnac_validator_record_t r;
        val_pk(GRAD, pk);
        CHECK(nodus_validator_get(w, pk, &r) == 0 &&
              r.status == (uint8_t)DNAC_VALIDATOR_UNSTAKED &&
              r.self_stake == 0 && r.total_delegated == 0 &&
              r.external_delegated == 0, "the graduate is emptied");
    }
    {
        char sql[128];
        snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM v2_balance_copy "
                 "WHERE epoch_start = %llu", (unsigned long long)E);
        CHECK(q1(w, sql) == (int64_t)N_VAL * (1 + N_DEL),
              "copy(E): 32 bonds + 32 × 2048 delegations");
    }
    CHECK(q1(w, "SELECT COUNT(*) FROM v2_reward_accrual") ==
              (int64_t)N_VAL * (1 + N_DEL),
          "every one of the 65 568 recipients accrued a nonzero share");
    CHECK(nodus_witness_v2_supply_check(w) == 0,
          "the supply equation closes after the boundary");

    /* ── (2) THE PAYDAY over every accrual row ──────────────────────── */
    uint32_t n_paid = 0;
    CHECK(run_sql(w->db, "BEGIN IMMEDIATE") == 0, "begin payday");
    const double t_p0 = now_ms();
    const int prc = nodus_witness_v2_payday_apply(w, E, 1, NULL, NULL,
                                                  &n_paid);
    const double t_p1 = now_ms();
    CHECK(prc == 0, "the payday applies");
    CHECK(run_sql(w->db, "COMMIT") == 0, "commit payday");
    CHECK(n_paid == (uint32_t)(N_VAL * (1 + N_DEL)),
          "the payday paid all 65 568 rows");
    CHECK(q1(w, "SELECT COUNT(*) FROM v2_reward_accrual") == 0,
          "the accrual table is empty");
    CHECK(nodus_witness_v2_supply_check(w) == 0,
          "the supply equation closes after the payday");

    /* ── the numbers ─────────────────────────────────────────────────── */
    const double *s = g_stage_ms;
    printf("MEASURED (ms, wall clock, one run, this machine):\n");
    printf("  fixture seed (33 validators, %d delegations): %10.1f\n",
           (N_VAL + 1) * N_DEL, t_seed1 - t_seed0);
    printf("  engine genesis incl. copy(0) (%d rows):       %10.1f\n",
           (N_VAL + 1) * (1 + N_DEL), t_gen1 - t_gen0);
    printf("  BOUNDARY at E, total:                          %10.1f\n",
           t_b1 - t_b0);
    printf("    distribution (32 x 2048, accrue + debit):    %10.1f\n",
           s[NODUS_V2_EPST_DIST_APPLIED] - s[NODUS_V2_EPST_COMMISSIONS]);
    printf("    graduation: 2048-delegation auto-release:    %10.1f\n",
           s[NODUS_V2_EPST_GRAD_DELEG_RELEASED] -
               s[NODUS_V2_EPST_GRAD_RELEASE]);
    printf("    graduation total (bond + delegations + row): %10.1f\n",
           s[NODUS_V2_EPST_GRAD_BATCH] - s[NODUS_V2_EPST_DIST_APPLIED]);
    printf("    Rule N (incl. nothing to retire):            %10.1f\n",
           s[NODUS_V2_EPST_RULE_N] - s[NODUS_V2_EPST_GRAD_BATCH]);
    printf("    next snapshot (okuma B over copy(0)):        %10.1f\n",
           s[NODUS_V2_EPST_SNAPSHOT_PERSIST] -
               s[NODUS_V2_EPST_SNAPSHOT_BUILD]);
    printf("    balance copy write (%d rows) + prune:     %10.1f\n",
           N_VAL * (1 + N_DEL),
           s[NODUS_V2_EPST_BALANCE_COPY] - s[NODUS_V2_EPST_SNAPSHOT_PERSIST]);
    printf("  PAYDAY over %u accrual rows:                %10.1f\n",
           (unsigned)n_paid, t_p1 - t_p0);
    printf("  (reference: cometbft timeout_commit 4000 ms — design §8 "
           "P3-6; the per-block root recomputation is NOT included, see "
           "the header's HOW IT CAN LIE)\n");

    sqlite3_close(w->db);
    free(w);
    rmrf(dir);
    printf("test_v2_deleg_cap_bench: OK (correctness only; times are "
           "informational)\n");
    return 0;
}
