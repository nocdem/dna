/**
 * @file nodus/tests/test_v2_treasury.c
 * @brief Final pre-testnet wipe, package W-A — the keyless, locked
 *        treasury pools.
 *
 * Decision: docs/plans/decisions/2026-09-28-treasury-pools-and-exact-
 * self-stake.md (answers 7, 9, 11, 12, 13). Design:
 * docs/plans/2026-09-28-final-wipe-package-design.md §1 W-A.
 *
 * WHAT IT PROVES (each section names the property that would be false
 * if it failed):
 *   §1 the genesis rules — the pool set is exactly pool_id 1..9 in
 *      index order; a balance above INT64_MAX is refused; Rule P.2
 *      counts Σ treasury (over- and under-allocation by one raw unit
 *      both refuse, the exact composition is accepted); _v3_defaults
 *      writes the pool IDS and never the balances.
 *   §2 the derivation SEEDS `v2_treasury` with exactly the document's
 *      nine rows, the claimable distribution excludes them, the supply
 *      equation closes over them at genesis, and a different treasury
 *      split (same total) is a different chain.
 *   §3 the supply equation carries the treasury term — a pool balance
 *      that moves by one raw unit with nothing moving the other way
 *      breaks it; a malformed pool row faults it.
 *   §4 THROUGH THE ENGINE: a genesis seat with no delegations graduating
 *      ALONE at a boundary releases its bond as a locked UTXO to its
 *      destination — a MULTISIG address (general multisig, decision
 *      2026-09-29-general-multisig.md, which withdrew W-A's pool-8
 *      refund): the block commits, CORE moves, pool 8 does not.
 *   §5 general multisig, config_version 5: pools 5-9 as GENESIS OUTPUTS
 *      to a multisig address — the coin identity against the oracle
 *      (pinned oracle KATs), exact count / Σ / fields in utxo_set,
 *      not claimable, supply closes at genesis, Rule P.2 counts them.
 *
 * WHAT IT REQUIRES: a default build (no -D, no environment). §2 derives
 * real chains, §4 seeds one, into mkdtemp directories under /tmp and
 * removes them. §4 drives DNAC_EPOCH_LENGTH zero-envelope blocks (720 at
 * the shipped constant).
 *
 * WHAT IT LEAVES BEHIND: nothing (every chain directory is removed).
 *
 * HOW IT CAN LIE:
 *   - §3 edits pool rows by direct UPDATE, not through a block; it
 *     proves the EQUATION, not a block path (no block path writes a
 *     pool after genesis in this build).
 *   - §4's genesis is seeded (a RETIRING row at genesis), not derived.
 *   - The treasury ROOT layout itself is pinned by test_roots_v2.c
 *     (oracle KATs); here it is only compared against the shared
 *     function.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "v2_genesis_fixture.h"

#include "dnac/ledger_roots_v2.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_gen.h"
#include "witness/nodus_witness_v2_epoch.h"   /* grad_id / nullifier (§4) */
#include "witness/nodus_witness_v2_apply.h"   /* the block (§4)          */
#include "dnac/cmt_pb.h"                      /* CMT_PB_BLOCK_ID_FLAG_COMMIT */
#include "dnac/msig_wire.h"                   /* the multisig destination */

static int g_checks = 0;

#define CHECK(cond, msg) do {                                              \
    if (!(cond)) {                                                         \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg));                                                    \
        return 1;                                                          \
    }                                                                      \
    g_checks++;                                                            \
} while (0)

/* The decision's nine pool amounts, whole NODUS, pool order = answer 11:
 * 1 Storage, 2 Compute, 3 VPN/Bandwidth, 4 Future services, 5 Security/
 * bug bounty, 6 Liquidity, 7 Ecosystem grants, 8 Foundation (100M − the
 * 7 × 10M genesis stakes), 9 Community airdrop.
 * Σ = 100+100+50+50+50+150+100+30+50 = 680M. (The decision file's
 * "Toplam 730M" line is 680M + the 50M Founder allocation, which is NOT
 * a pool — decision §Karar 3.) */
static const uint64_t POOL_WHOLE[NODUS_V2_GEN_TREASURY_POOLS] = {
    100000000ULL, 100000000ULL, 50000000ULL, 50000000ULL, 50000000ULL,
    150000000ULL, 100000000ULL, 30000000ULL, 50000000ULL
};
#define RAW_PER_NODUS   100000000ULL
#define TREASURY_TOTAL  (680000000ULL * RAW_PER_NODUS)
#define REWARD_POOL     (200000000ULL * RAW_PER_NODUS)
#define FOUNDER_ALLOC   (50000000ULL * RAW_PER_NODUS)

/* v2x_cfg_make + the decision's composition (Rule P.2):
 *   1B = 680M treasury + 200M reward pool + 50M Founder allocation
 *        + 7 × 10M self-stake
 * at the shipped constants (10^17 raw total, 10^8 raw per NODUS). The
 * fixture's single allocation becomes the Founder's 50M. Refuses (-1) at
 * any build whose constants make that composition not close. */
static int cfg_with_treasury(v2x_cfgbox_t *b, uint8_t salt) {
    if (v2x_cfg_make(b, salt) != 0) return -1;
    uint64_t sum = 0;
    for (size_t i = 0; i < NODUS_V2_GEN_TREASURY_POOLS; i++) {
        b->cfg->treasury[i].balance = POOL_WHOLE[i] * RAW_PER_NODUS;
        sum += b->cfg->treasury[i].balance;
    }
    b->cfg->reward_pool_initial = REWARD_POOL;
    if (sum != TREASURY_TOTAL ||
        b->allocs[0].amount != sum + REWARD_POOL + FOUNDER_ALLOC) {
        v2x_cfg_free(b);
        return -1;
    }
    b->allocs[0].amount = FOUNDER_ALLOC;
    return 0;
}

static int64_t q1(sqlite3 *db, const char *sql) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -99;
    int64_t v = -98;
    if (sqlite3_step(st) == SQLITE_ROW) v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

static int exec(sqlite3 *db, const char *sql) {
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}

/* ── §1 the genesis rules ─────────────────────────────────────────────── */
static int test_rules(void) {
    printf("§1 the treasury genesis rules\n");
    v2x_cfgbox_t b;

    /* _v3_defaults: structural pool ids, balances untouched */
    CHECK(v2x_cfg_make(&b, 0) == 0, "fixture");
    for (size_t i = 0; i < NODUS_V2_GEN_TREASURY_POOLS; i++)
        CHECK(b.cfg->treasury[i].pool_id == (uint32_t)(i + 1) &&
              b.cfg->treasury[i].balance == 0,
              "_v3_defaults writes pool_id i + 1 and leaves the balance");
    b.cfg->treasury[4].balance = 77;
    CHECK(nodus_witness_v2_gen_v3_defaults(b.cfg) == 0 &&
          b.cfg->treasury[4].balance == 77,
          "_v3_defaults never overwrites a treasury balance");
    CHECK(b.cfg->config_version == NODUS_V2_GEN_CONFIG_VERSION_V5,
          "_v3_defaults writes config_version 5 (general multisig)");
    v2x_cfg_free(&b);

    /* the all-zero treasury is a legal document (JUDGMENT, header) */
    CHECK(v2x_cfg_make(&b, 0) == 0, "fixture");
    CHECK(nodus_witness_v2_gen_v3_validate(b.cfg) == 0,
          "a document with nine zero pools is ACCEPTED");
    v2x_cfg_free(&b);

    /* Rule P.2 counts Σ treasury — KILLED BY dropping treasury_total
     * from either sum in gen_plan_build. */
    CHECK(cfg_with_treasury(&b, 0) == 0, "fixture + treasury");
    CHECK(nodus_witness_v2_gen_v3_validate(b.cfg) == 0,
          "P.2: allocations + bonds + reserve + Σ treasury == total is "
          "ACCEPTED");
    b.allocs[0].amount += 1;
    CHECK(nodus_witness_v2_gen_v3_validate(b.cfg) != 0,
          "P.2: over-allocation by 1 next to the treasury REJECTS");
    b.allocs[0].amount -= 2;
    CHECK(nodus_witness_v2_gen_v3_validate(b.cfg) != 0,
          "P.2: under-allocation by 1 next to the treasury REJECTS");
    b.allocs[0].amount += 1;
    b.allocs[0].amount += TREASURY_TOTAL;
    CHECK(nodus_witness_v2_gen_v3_validate(b.cfg) != 0,
          "P.2: a treasury on top of a fully-spent supply REJECTS");
    b.allocs[0].amount -= TREASURY_TOTAL;
    CHECK(nodus_witness_v2_gen_v3_validate(b.cfg) == 0, "restored");

    /* the pool set — KILLED BY dropping the pool_id == i + 1 check */
    b.cfg->treasury[2].pool_id = 5;
    CHECK(nodus_witness_v2_gen_v3_validate(b.cfg) != 0,
          "entry 2 carrying pool_id 5 REJECTS");
    b.cfg->treasury[2].pool_id = 3;
    b.cfg->treasury[0].pool_id = 0;
    CHECK(nodus_witness_v2_gen_v3_validate(b.cfg) != 0,
          "pool_id 0 REJECTS");
    b.cfg->treasury[0].pool_id = 1;
    b.cfg->treasury[8].pool_id = 10;
    CHECK(nodus_witness_v2_gen_v3_validate(b.cfg) != 0,
          "pool_id 10 REJECTS");
    b.cfg->treasury[8].pool_id = 9;
    {
        nodus_v2_gen_treasury_t t = b.cfg->treasury[3];
        b.cfg->treasury[3] = b.cfg->treasury[4];
        b.cfg->treasury[4] = t;
        CHECK(nodus_witness_v2_gen_v3_validate(b.cfg) != 0,
              "two entries out of order REJECT (no normalising sort)");
        t = b.cfg->treasury[3];
        b.cfg->treasury[3] = b.cfg->treasury[4];
        b.cfg->treasury[4] = t;
    }
    CHECK(nodus_witness_v2_gen_v3_validate(b.cfg) == 0, "restored");
    v2x_cfg_free(&b);

    /* the signed storage bound */
    CHECK(v2x_cfg_make(&b, 0) == 0, "fixture");
    b.cfg->treasury[7].balance = (uint64_t)INT64_MAX + 1ULL;
    CHECK(nodus_witness_v2_gen_v3_validate(b.cfg) != 0,
          "a balance above INT64_MAX REJECTS");
    v2x_cfg_free(&b);

    printf("  ok\n");
    return 0;
}

/* ── §2 the derivation seeds the table ────────────────────────────────── */
static int test_derive(void) {
    printf("§2 the derivation seeds v2_treasury\n");
    v2x_cfgbox_t b;
    CHECK(cfg_with_treasury(&b, 0) == 0, "fixture + treasury");
    const uint64_t alloc = b.allocs[0].amount;
    v2x_chain_t c;
    CHECK(v2x_chain_open_cfg(&c, "treasury", &b) == 0,
          "the composition derives and reopens");
    sqlite3 *db = c.w->db;

    CHECK(q1(db, "SELECT COUNT(*) FROM v2_treasury") ==
              (int64_t)NODUS_V2_GEN_TREASURY_POOLS,
          "exactly nine pool rows");
    for (size_t i = 0; i < NODUS_V2_GEN_TREASURY_POOLS; i++) {
        char sql[96];
        snprintf(sql, sizeof(sql),
                 "SELECT balance FROM v2_treasury WHERE pool_id = %zu", i + 1);
        CHECK(q1(db, sql) == (int64_t)(POOL_WHOLE[i] * RAW_PER_NODUS),
              "each pool holds the document's balance");
    }
    {
        uint64_t tot = 0;
        CHECK(nodus_witness_treasury_total(c.w, &tot) == 0 &&
              tot == TREASURY_TOTAL, "the loader's total is 680M NODUS");
    CHECK(q1(db, "SELECT reward_pool FROM supply_tracking WHERE id=1")
              == (int64_t)REWARD_POOL,
          "the 200M reward pool is seeded next to the treasury");
    }
    CHECK(q1(db, "SELECT COALESCE(SUM(remaining),-1) FROM v2_dist_state")
              == (int64_t)alloc,
          "the claimable distribution is the allocation only — the "
          "treasury is not claimable");
    CHECK(q1(db, "SELECT genesis_supply FROM supply_tracking WHERE id=1")
              == (int64_t)DNAC_DEFAULT_TOTAL_SUPPLY,
          "the genesis supply is the FIXED total (the pools are carved "
          "out of it)");
    CHECK(nodus_witness_v2_supply_check(c.w) == 0,
          "the supply equation closes over the treasury at genesis");

    /* the loader and the payload root agree with the shared layer */
    {
        uint32_t ids[NODUS_V2_GEN_TREASURY_POOLS];
        uint64_t bals[NODUS_V2_GEN_TREASURY_POOLS];
        for (size_t i = 0; i < NODUS_V2_GEN_TREASURY_POOLS; i++) {
            ids[i] = (uint32_t)(i + 1);
            bals[i] = POOL_WHOLE[i] * RAW_PER_NODUS;
        }
        uint8_t want[64], got[64];
        CHECK(dna_v2_treasury_root(ids, bals, NODUS_V2_GEN_TREASURY_POOLS,
                                   want) == 0 &&
              nodus_witness_treasury_root_v2(c.w, got) == 0 &&
              memcmp(want, got, 64) == 0,
              "treasury_root on the derived chain == the shared root over "
              "the document's pools");
    }
    uint8_t id_a[NODUS_V2_GEN_CHAIN_ID_LEN];
    memcpy(id_a, c.chain32, sizeof(id_a));
    v2x_chain_close(&c);

    /* the SAME total split differently is a DIFFERENT chain — the
     * treasury reaches the chain id (the document) AND the ledger. */
    CHECK(cfg_with_treasury(&b, 0) == 0, "fixture + treasury");
    b.cfg->treasury[0].balance -= 1;
    b.cfg->treasury[7].balance += 1;
    CHECK(v2x_chain_open_cfg(&c, "treasury_b", &b) == 0,
          "the re-split composition derives");
    CHECK(memcmp(id_a, c.chain32, sizeof(id_a)) != 0,
          "a different pool split is a different chain id");
    v2x_chain_close(&c);

    printf("  ok\n");
    return 0;
}

/* ── §3 the supply term ───────────────────────────────────────────────── */
static int test_supply_term(void) {
    printf("§3 the supply equation carries the treasury term\n");
    v2x_cfgbox_t b;
    CHECK(cfg_with_treasury(&b, 0x10) == 0, "fixture + treasury");
    v2x_chain_t c;
    CHECK(v2x_chain_open_cfg(&c, "treasury_sup", &b) == 0, "derive");
    sqlite3 *db = c.w->db;
    CHECK(nodus_witness_v2_supply_check(c.w) == 0, "closed at genesis");

    /* KILLED BY dropping `+ treasury` from nodus_rt_core_invariant. */
    CHECK(exec(db, "UPDATE v2_treasury SET balance = balance + 1 "
                   "WHERE pool_id = 3") == 0, "conjure 1 raw unit");
    CHECK(nodus_witness_v2_supply_check(c.w) != 0,
          "a pool balance conjured from nothing BREAKS the equation");
    CHECK(exec(db, "UPDATE v2_treasury SET balance = balance - 1 "
                   "WHERE pool_id = 3") == 0, "restore");
    CHECK(nodus_witness_v2_supply_check(c.w) == 0, "closed again");
    /* a malformed row faults the equation rather than being summed */
    CHECK(exec(db, "INSERT INTO v2_treasury (pool_id, balance) "
                   "VALUES (10, 0)") == 0, "out-of-set row");
    CHECK(nodus_witness_v2_supply_check(c.w) != 0,
          "an out-of-set pool row FAULTS the equation");
    CHECK(exec(db, "DELETE FROM v2_treasury WHERE pool_id = 10") == 0,
          "cleanup");
    v2x_chain_close(&c);

    printf("  ok\n");
    return 0;
}

/* ── §4 the boundary: a genesis seat graduates ALONE ──────────────────
 * General multisig (decision 2026-09-29-general-multisig.md, operator
 * answer: the seven genesis validators' self-stake returns to the
 * FOUNDATION MULTISIG ADDRESS) withdrew W-A's refund of a genesis seat's
 * bond into treasury pool 8. A genesis row's unstake destination is a
 * 64-byte ADDRESS — here a 2-of-3 multisig address (msig_wire.h) — and
 * the graduation releases the bond to it as a locked UTXO exactly like
 * any other seat's.
 *
 * The chain: a SEEDED version-3 genesis (v2_genesis_fixture.h TIER B)
 * with six ACTIVE seats and one RETIRING genesis seat (key 6,
 * active_since_block 1, no delegations, destination = the Foundation-
 * style 2-of-3 address over keys 0..2 — so it is in neither committed
 * snapshot and graduates at the first boundary E), the nine treasury
 * rows, reward pool 0 (the distribution credits nothing) and E below
 * the first payday. Zero-envelope blocks up to E, each carrying a
 * full-committee commit vote (Rule N stays a no-op), the test as host.
 *
 * PROVES: the boundary block at E COMMITS; CORE's state root MOVED (the
 * release is a utxo_set row, so phase 6e declares CORE on the graduate
 * count — a missing declaration would have been refused); pool 8 did NOT
 * move; exactly one UTXO appeared, under the graduation's nullifier,
 * owned by the MULTISIG ADDRESS (128 hex), amount = the bond, locked to
 * E + DNAC_VALIDATOR_UNBOND_EPOCHS·E; the seat is UNSTAKED with a zero
 * bond; the supply equation closes. KILLED BY: restoring the pool-8
 * refund (no UTXO, pool 8 grows); a phase 6e that declares CORE on
 * anything but a graduate/accrual/payday (the block is refused).
 * HOW IT CAN LIE: the genesis is seeded, not derived (named
 * V2X_SEED_NOT_REAL_STATUSES — a real genesis writes only ACTIVE rows);
 * the RETIRING state is pre-chain, not produced by an UNSTAKE block;
 * the multisig keys are synthetic byte patterns (the address is only
 * compared, never spent here — spending it is test_v2_native's). */
#define TR_NKEYS 7
static uint8_t g_tpk[TR_NKEYS][DNAC_PUBKEY_SIZE];
static char    g_tfp[TR_NKEYS][129];

static void tr_keys_init(void) {
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < TR_NKEYS; i++) {
        for (int b = 0; b < DNAC_PUBKEY_SIZE; b++)
            g_tpk[i][b] = (uint8_t)((b * 29u + i * 13u + 5u) & 0xFF);
        g_tpk[i][0] = (uint8_t)(0x20 + i);
        uint8_t full[64];
        qgp_sha3_512(g_tpk[i], DNAC_PUBKEY_SIZE, full);
        for (int b = 0; b < 64; b++) {
            g_tfp[i][2 * b]     = hexd[full[b] >> 4];
            g_tfp[i][2 * b + 1] = hexd[full[b] & 0xF];
        }
        g_tfp[i][128] = '\0';
    }
}

/* One zero-envelope block at `h`, with a COMMIT vote from every ACTIVE
 * seat (the test_v2_epoch fx_block shape). 0 = committed. */
static int tr_block(nodus_witness_t *w, uint64_t h) {
    nodus_v2_block_t b;
    memset(&b, 0, sizeof(b));
    b.global_height = h;
    b.epoch = nodus_v2_epoch_for_height(h);
    uint8_t addrs[TR_NKEYS][32];
    int32_t flags[TR_NKEYS];
    if (h > 1) {
        size_t n = 0;
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db, "SELECT pubkey FROM validators "
                               "WHERE status = ?1", -1, &st, NULL)
            != SQLITE_OK)
            return -1;
        sqlite3_bind_int(st, 1, (int)DNAC_VALIDATOR_ACTIVE);
        while (sqlite3_step(st) == SQLITE_ROW && n < TR_NKEYS) {
            uint8_t d[64];
            if (sqlite3_column_bytes(st, 0) != DNAC_PUBKEY_SIZE ||
                qgp_sha3_512(sqlite3_column_blob(st, 0), DNAC_PUBKEY_SIZE,
                             d) != 0) {
                sqlite3_finalize(st);
                return -1;
            }
            memcpy(addrs[n], d, 32);
            flags[n] = CMT_PB_BLOCK_ID_FLAG_COMMIT;
            n++;
        }
        sqlite3_finalize(st);
        if (n > 0) {
            b.cmt.votes_address = (const uint8_t (*)[32])addrs;
            b.cmt.votes_block_id_flag = flags;
            b.cmt.votes_len = n;
        }
    }
    return v2x_cmt_apply(w, &b) == 0 ? 0 : -1;
}

static int test_boundary_genesis_seat_alone(void) {
    printf("§4 a genesis seat graduates ALONE at a boundary\n");
    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    tr_keys_init();

    /* the Foundation-style destination: 2-of-3 over keys 0..2 (strictly
     * ascending by construction — byte 0 is 0x20 + i) */
    char msig_fp[129];
    {
        static const char hexd[] = "0123456789abcdef";
        uint8_t keys[3 * DNAC_PUBKEY_SIZE];
        uint8_t desc[DNA_MSIG_MAX_DESC_LEN];
        uint8_t addr[64];
        size_t dlen = 0;
        for (int i = 0; i < 3; i++)
            memcpy(keys + (size_t)i * DNAC_PUBKEY_SIZE, g_tpk[i],
                   DNAC_PUBKEY_SIZE);
        CHECK(dna_msig_desc_encode(2, 3, keys, desc, sizeof(desc),
                                   &dlen) == 0 &&
              dna_msig_address(desc, dlen, addr) == 0,
              "2-of-3 Foundation-style address");
        for (int b = 0; b < 64; b++) {
            msig_fp[2 * b]     = hexd[addr[b] >> 4];
            msig_fp[2 * b + 1] = hexd[addr[b] & 0xF];
        }
        msig_fp[128] = '\0';
    }

    nodus_witness_t *w = calloc(1, sizeof(*w));   /* multi-MB: heap */
    CHECK(w != NULL, "alloc");
    char dir[128];
    snprintf(dir, sizeof(dir), "/tmp/test_v2_treasury_bnd_XXXXXX");
    CHECK(mkdtemp(dir) != NULL, "tmpdir");
    snprintf(w->data_path, sizeof(w->data_path), "%s", dir);
    uint8_t file16[16];
    memset(file16, 0x5B, sizeof(file16));
    CHECK(v2x_seed_prepare(w, file16, 0) == 0, "seed prepare");

    /* six ACTIVE seats + one RETIRING genesis seat, all bonded 10M */
    uint64_t bonds = 0;
    for (int k = 0; k < TR_NKEYS; k++) {
        dnac_validator_record_t v;
        memset(&v, 0, sizeof(v));
        memcpy(v.pubkey, g_tpk[k], DNAC_PUBKEY_SIZE);
        v.self_stake = (uint64_t)DNAC_SELF_STAKE_AMOUNT;
        v.status = (uint8_t)(k == 6 ? DNAC_VALIDATOR_RETIRING
                                    : DNAC_VALIDATOR_ACTIVE);
        v.active_since_block = 1;          /* a GENESIS seat */
        v.commission_bps = 100;
        v.unstake_commit_block = (k == 6) ? 1 : 0;
        /* the graduating genesis seat pays the MULTISIG address */
        memcpy(v.unstake_destination_fp, k == 6 ? msig_fp : g_tfp[k], 129);
        CHECK(nodus_validator_insert(w, &v) == 0, "validator row");
        bonds += v.self_stake;
    }
    /* the nine pools (the decision's balances) */
    uint64_t treasury = 0;
    for (size_t i = 0; i < NODUS_V2_GEN_TREASURY_POOLS; i++) {
        char sql[128];
        snprintf(sql, sizeof(sql), "INSERT INTO v2_treasury (pool_id, "
                 "balance) VALUES (%zu, %llu)", i + 1,
                 (unsigned long long)(POOL_WHOLE[i] * RAW_PER_NODUS));
        CHECK(exec(w->db, sql) == 0, "treasury row");
        treasury += POOL_WHOLE[i] * RAW_PER_NODUS;
    }
    /* supply = bonds + treasury, reward pool 0 (nothing to distribute) */
    {
        uint8_t src[64];
        memset(src, 0x77, sizeof(src));
        CHECK(nodus_witness_supply_init(w, bonds + treasury, 0, src) == 0,
              "supply row");
    }
    /* not a real genesis: a RETIRING row at genesis (the subject) */
    v2x_seed_not_real(V2X_SEED_NOT_REAL_STATUSES);
    CHECK(v2x_seed_genesis(w, file16, 0, NULL, 0, NULL) == 0,
          "seeded genesis commits");
    CHECK(nodus_witness_v2_supply_check(w) == 0, "closed at genesis");

    for (uint64_t h = 1; h < E; h++)
        CHECK(tr_block(w, h) == 0, "drive to E-1");

    uint8_t sys0[64], core0[64], sys1[64], core1[64];
    CHECK(nodus_witness_system_root_v2(w, sys0) == 0 &&
          nodus_witness_core_root_v2(w, core0) == 0, "roots at E-1");
    const int64_t pool8_0 =
        q1(w->db, "SELECT balance FROM v2_treasury WHERE pool_id = 8");
    const int64_t utxos_0 = q1(w->db, "SELECT COUNT(*) FROM utxo_set");

    /* THE BOUNDARY BLOCK */
    CHECK(tr_block(w, E) == 0,
          "the boundary block where a genesis seat graduates ALONE "
          "COMMITS");

    CHECK(nodus_witness_system_root_v2(w, sys1) == 0 &&
          nodus_witness_core_root_v2(w, core1) == 0, "roots at E");
    CHECK(memcmp(core0, core1, 64) != 0,
          "CORE's state root moved — the bond release is a utxo_set row");
    CHECK(memcmp(sys0, sys1, 64) != 0, "the SYSTEM root moved");
    CHECK(q1(w->db, "SELECT balance FROM v2_treasury WHERE pool_id = 8")
              == pool8_0,
          "pool 8 did NOT move — no treasury refund any more");
    CHECK(q1(w->db, "SELECT COUNT(*) FROM utxo_set") == utxos_0 + 1,
          "exactly one UTXO was written by the graduation");
    {
        uint8_t chain[DNA_CHAIN_ID_LEN], gid[64], nul[64];
        CHECK(nodus_witness_v2_chain_id(w, chain) == 0 &&
              nodus_witness_v2_epoch_grad_id(chain, E, g_tpk[6], gid) == 0 &&
              nodus_witness_v2_epoch_grad_nullifier(gid, nul) == 0,
              "grad nullifier");
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(w->db, "SELECT owner, amount, unlock_block "
                                 "FROM utxo_set WHERE nullifier = ?1", -1,
                                 &st, NULL) == SQLITE_OK, "prepare");
        sqlite3_bind_blob(st, 1, nul, 64, SQLITE_TRANSIENT);
        int row = (sqlite3_step(st) == SQLITE_ROW);
        const unsigned char *own = row ? sqlite3_column_text(st, 0) : NULL;
        int own_ok = own && sqlite3_column_bytes(st, 0) == 128 &&
                     memcmp(own, msig_fp, 128) == 0;
        int64_t amt = row ? sqlite3_column_int64(st, 1) : -1;
        int64_t unl = row ? sqlite3_column_int64(st, 2) : -1;
        sqlite3_finalize(st);
        CHECK(row, "the release UTXO sits under the graduation's nullifier");
        CHECK(own_ok, "owned by the Foundation-style MULTISIG address");
        CHECK(amt == (int64_t)DNAC_SELF_STAKE_AMOUNT,
              "amount = the 10M bond");
        CHECK(unl == (int64_t)(E + (uint64_t)DNAC_VALIDATOR_UNBOND_EPOCHS * E),
              "locked for DNAC_VALIDATOR_UNBOND_EPOCHS epochs from E");
    }
    {
        dnac_validator_record_t v;
        CHECK(nodus_validator_get(w, g_tpk[6], &v) == 0, "seat 6");
        CHECK(v.status == (uint8_t)DNAC_VALIDATOR_UNSTAKED &&
              v.self_stake == 0, "the seat is UNSTAKED with a zero bond");
    }
    CHECK(nodus_witness_v2_supply_check(w) == 0,
          "the bond moved into utxo_set: the equation closes");

    sqlite3_close(w->db);
    free(w);
    {
        char cmd[200];
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
        if (system(cmd) != 0) { /* best effort */ }
    }
    printf("  ok\n");
    return 0;
}

/* ── §5 general multisig — the GENESIS OUTPUTS (config_version 5) ──────
 * Decision 2026-09-29-general-multisig.md ONAY 2 + design §7 rev 2: the
 * Foundation's pools 5-9 become GENESIS OUTPUTS to the Foundation's
 * multisig address (treasury rows 5-9 hold 0), written straight into
 * utxo_set by the derivation.
 *
 * PROVES: (a) the coin identity function against the independent oracle
 * (pinned from multisig_oracle.py, ONAY 2 source_commit form);
 * (b) a derived chain holds EXACTLY the five outputs — count and Σ — each
 * with nullifier = tx_hash = SHA3-512("DNA.GENOUT.v1" ‖ source_commit ‖
 * i) for its DOCUMENT index i, owner = the multisig address (128 hex),
 * the document's amount, output_index 0, block_height 0, unlock 0,
 * domain CORE, native token; (c) the claimable distribution EXCLUDES
 * them; (d) the supply equation closes at genesis; (e) moving one raw
 * unit from an output to the allocation is a different chain, and an
 * extra raw unit anywhere refuses (Rule P.2).
 * KILLED BY: seeding after the root / keying the id on chain_id (the
 * derivation's own app_hash post-condition, and the id compare);
 * counting outputs as claimable; sorting outputs.
 * HOW IT CAN LIE: (a) proves only that C and the oracle implement the
 * same written layout; the multisig owner here is a synthetic address
 * (spending it is test_v2_native §MSIG's subject). */
/* PINNED 2026-09-29 from shared/dnac/tests/multisig_oracle.py genout_nullifier
 * (source_commit form, ONAY 2), evaluated at source_commit = 64 x 0x11. */
static const char *KAT_GENOUT_SC11_0 =
    "217b314f566e50459e2f2f382d8d91c30e78e1b4a60dc657a9e1e02b9eaf299fe16ec1f40e0669b544e0df98baedcde4fbd27d2103c710cea35ff80c23206396";
static const char *KAT_GENOUT_SC11_1 =
    "084d87014063fb3b9109b11c2dfe5b460d71423363024cb6cc1683575e5d8f652b4867948a198ec040f405e49ff6b3c06a8765222cec52c195cf1bb7e5ec873d";
static const char *KAT_GENOUT_SC11_2 =
    "a78e018db93e15841880456af7a6036a35e8616626267a653d9ea9fad400c966fca34b10f9a897db672a10cbd258b8e91d64850a4cafcd0e990513602cde239a";

/* cfg_with_treasury + the decision's move: pools 5-9 become genesis
 * outputs 0-4 (same amounts, document order = pool order) owned by
 * `addr`; treasury rows 5-9 hold 0. Rule P.2 unchanged. 0 / -1. */
static int cfg_genout(v2x_cfgbox_t *b, const uint8_t addr[64]) {
    if (cfg_with_treasury(b, 0x21) != 0) return -1;
    b->cfg->n_genesis_outputs = 5;
    for (uint32_t i = 0; i < 5; i++) {
        memcpy(b->cfg->genesis_outputs[i].owner, addr, 64);
        b->cfg->genesis_outputs[i].amount = b->cfg->treasury[4 + i].balance;
        b->cfg->treasury[4 + i].balance = 0;
    }
    return 0;
}

static int hex_is(const uint8_t *b, size_t n, const char *hex) {
    static const char hexd[] = "0123456789abcdef";
    if (!hex || strlen(hex) != 2 * n) return 0;
    for (size_t i = 0; i < n; i++)
        if (hex[2 * i] != hexd[b[i] >> 4] ||
            hex[2 * i + 1] != hexd[b[i] & 0xF])
            return 0;
    return 1;
}

static int test_genesis_outputs(void) {
    printf("§5 the genesis outputs (general multisig, config_version 5)\n");

    /* (a) the identity function, vectors from the oracle */
    {
        uint8_t sc[NODUS_V2_GEN_SRCCOMMIT_LEN], n[64];
        memset(sc, 0x11, sizeof(sc));
        const char *kat[3] = { KAT_GENOUT_SC11_0, KAT_GENOUT_SC11_1,
                               KAT_GENOUT_SC11_2 };
        for (uint32_t i = 0; i < 3; i++) {
            CHECK(nodus_witness_v2_gen_output_nullifier(sc, i, n) == 0,
                  "genout nullifier");
            if (!hex_is(n, 64, kat[i])) {
                fprintf(stderr, "genout KAT %u mismatch (placeholder not "
                        "yet pasted from multisig_oracle.py?)\n",
                        (unsigned)i);
                return 1;
            }
            g_checks++;
        }
    }

    /* the Foundation-style 2-of-3 address (synthetic keys) */
    uint8_t addr[64];
    char addr_hex[129];
    {
        static const char hexd[] = "0123456789abcdef";
        uint8_t keys[3 * DNAC_PUBKEY_SIZE];
        uint8_t desc[DNA_MSIG_MAX_DESC_LEN];
        size_t dlen = 0;
        for (int k = 0; k < 3; k++)
            memset(keys + (size_t)k * DNAC_PUBKEY_SIZE, 0x41 + k,
                   DNAC_PUBKEY_SIZE);
        CHECK(dna_msig_desc_encode(2, 3, keys, desc, sizeof(desc),
                                   &dlen) == 0 &&
              dna_msig_address(desc, dlen, addr) == 0, "2-of-3 address");
        for (int b = 0; b < 64; b++) {
            addr_hex[2 * b]     = hexd[addr[b] >> 4];
            addr_hex[2 * b + 1] = hexd[addr[b] & 0xF];
        }
        addr_hex[128] = '\0';
    }

    /* the decision's composition: pools 5-9 → genesis outputs */
    v2x_cfgbox_t b;
    CHECK(cfg_genout(&b, addr) == 0, "fixture + treasury + outputs");
    uint64_t gsum = 0, gamt[5];
    for (uint32_t i = 0; i < 5; i++) {
        gamt[i] = b.cfg->genesis_outputs[i].amount;
        gsum += gamt[i];
    }
    const uint64_t alloc = b.allocs[0].amount;
    uint8_t sc[NODUS_V2_GEN_SRCCOMMIT_LEN];
    CHECK(nodus_witness_v2_gen_v3_source_commit(b.cfg, sc) == 0,
          "source_commit of the document");

    v2x_chain_t c;
    CHECK(v2x_chain_open_cfg(&c, "genout", &b) == 0,
          "the composition with genesis outputs derives");
    sqlite3 *db = c.w->db;

    /* (b) exactly the outputs */
    CHECK(q1(db, "SELECT COUNT(*) FROM utxo_set") == 5,
          "exactly five genesis coins");
    CHECK(q1(db, "SELECT COALESCE(SUM(amount),0) FROM utxo_set") ==
              (int64_t)gsum, "Σ genesis coins == Σ document outputs");
    for (uint32_t i = 0; i < 5; i++) {
        uint8_t nul[64];
        CHECK(nodus_witness_v2_gen_output_nullifier(sc, i, nul) == 0,
              "expected identity");
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(db,
                  "SELECT owner, amount, output_index, block_height, "
                  "unlock_block, domain_id, (tx_hash = nullifier), "
                  "(token_id = zeroblob(64)) FROM utxo_set "
                  "WHERE nullifier = ?1", -1, &st, NULL) == SQLITE_OK,
              "prepare");
        sqlite3_bind_blob(st, 1, nul, 64, SQLITE_TRANSIENT);
        int row = sqlite3_step(st) == SQLITE_ROW;
        int ok = row &&
                 sqlite3_column_bytes(st, 0) == 128 &&
                 memcmp(sqlite3_column_text(st, 0), addr_hex, 128) == 0 &&
                 sqlite3_column_int64(st, 1) == (int64_t)gamt[i] &&
                 sqlite3_column_int64(st, 2) == 0 &&
                 sqlite3_column_int64(st, 3) == 0 &&
                 sqlite3_column_int64(st, 4) == 0 &&
                 sqlite3_column_int64(st, 5) == (int64_t)DNA_DOMAIN_CORE &&
                 sqlite3_column_int64(st, 6) == 1 &&
                 sqlite3_column_int64(st, 7) == 1;
        sqlite3_finalize(st);
        CHECK(ok, "genesis coin i: identity = tx_hash = GENOUT(source_"
                  "commit, i), owner = the multisig address, the "
                  "document's amount, index 0, height 0, unlocked, CORE, "
                  "native");
    }
    /* (c) not claimable; the treasury holds pools 1-4 only */
    CHECK(q1(db, "SELECT COALESCE(SUM(remaining),-1) FROM v2_dist_state")
              == (int64_t)alloc,
          "the claimable distribution is the allocation only — genesis "
          "outputs are not claimable");
    CHECK(q1(db, "SELECT COALESCE(SUM(balance),0) FROM v2_treasury "
                 "WHERE pool_id >= 5") == 0,
          "treasury rows 5-9 hold 0");
    /* (d) the supply equation closes over the coins */
    CHECK(nodus_witness_v2_supply_check(c.w) == 0,
          "the supply equation closes at genesis with the outputs");
    uint8_t id_a[NODUS_V2_GEN_CHAIN_ID_LEN];
    memcpy(id_a, c.chain32, sizeof(id_a));
    v2x_chain_close(&c);

    /* (e) one raw unit moved out of output 0 into the allocation is a
     * different chain; one raw unit too many is refused (Rule P.2)
     * (v2x_chain_open_cfg TAKES the box, so each variant is rebuilt) */
    CHECK(cfg_genout(&b, addr) == 0, "fixture");
    b.cfg->genesis_outputs[0].amount -= 1;
    b.allocs[0].amount += 1;
    CHECK(v2x_chain_open_cfg(&c, "genout_b", &b) == 0,
          "the re-split composition derives");
    CHECK(memcmp(id_a, c.chain32, sizeof(id_a)) != 0,
          "a different output amount is a different chain id");
    v2x_chain_close(&c);
    CHECK(cfg_genout(&b, addr) == 0, "fixture");
    b.cfg->genesis_outputs[0].amount += 1;
    CHECK(nodus_witness_v2_gen_config_validate(b.cfg) != 0,
          "an output one raw unit over the supply REFUSES (Rule P.2)");
    b.cfg->genesis_outputs[0].amount -= 1;
    CHECK(nodus_witness_v2_gen_config_validate(b.cfg) == 0,
          "control: the balanced composition validates");
    memset(b.cfg->genesis_outputs[1].owner, 0, 64);
    CHECK(nodus_witness_v2_gen_config_validate(b.cfg) != 0,
          "an all-zero genesis-output owner REFUSES");
    v2x_cfg_free(&b);

    printf("  ok\n");
    return 0;
}

int main(void) {
    printf("=== W-A — the keyless treasury pools ===\n");
    if (test_rules()) return 1;
    if (test_derive()) return 1;
    if (test_supply_term()) return 1;
    if (test_boundary_genesis_seat_alone()) return 1;
    if (test_genesis_outputs()) return 1;
    printf("test_v2_treasury: ALL %d CHECKS PASSED\n", g_checks);
    return 0;
}
