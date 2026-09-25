/**
 * Nodus — tokenomics-v3 P2: rewards, fees, the reward pool
 * (nodus_witness_v2_econ.{h,c}), driven through the REAL apply engine
 * wherever the fixture lane can reach the property, and through the
 * exported entry points where it cannot (named, per case).
 *
 * Governing records: docs/plans/decisions/2026-09-22-nodus-tokenomics-v3-
 * operator.md (§1 "Ödüller ve ücretler"; §3 "P2 tasarım soruları") and
 * the contract, docs/plans/2026-09-23-tokenomics-v3-consensus-binding-
 * design.md §7 (P2-1 … P2-9).
 *
 * This file REPLACES the O15J Faz 2 economics test (emission gate,
 * epoch_state snapshot blob, equal-per-seat burning settlement): every
 * one of those subjects is deleted by P2 (P2-4 / P2-6).
 *
 * Sections:
 *   §1  THE BALANCE COPY — genesis writes copy(0) (one row per bond and
 *       per delegation, raw-fp keyed); a boundary writes copy(H) and
 *       keeps H−2E, H−E and H (tokenomics-v3 P3-2; P2 kept two).
 *   §2  DISTRIBUTION MATH, through the engine at boundary E — payout =
 *       pool >> 16, 128-bit shares pro rata to the GOVERNING snapshot's
 *       power (design §7.1 "P2-6 rev 2"), the inner split (base on the
 *       entry's self_bond / total_stake, commission from the snapshot
 *       entry, delegators by their source-copy amount), every remainder
 *       in the pool, the pool debited by EXACTLY Σ accrued, the supply
 *       equation closing term by term.
 *   §3  REVISION 2 (design §7.1; decision file §3 2026-09-24 "DELEGATOR
 *       = VALIDATOR GİBİ"), all through the engine: §3 the inner split
 *       reads the SOURCE copy src(H) = H−3E (0 below 3E — P3-2, the copy
 *       the governing snapshot was built from under P3-1's "okuma B") at
 *       E, 2E, 3E and 4E; §3a the consistency gate — a tampered
 *       source-copy row
 *       FAULTS the boundary (-2) with the pool untouched; §3b a
 *       delegator that withdraws mid-epoch is still paid for the epoch
 *       and until its stake leaves the voting power, and not after;
 *       §3c a partial withdrawal + fresh top-up in one epoch: the
 *       withdrawn part paid only through L(h), the top-up first paid
 *       from the epoch whose governing snapshot was built after it, and
 *       never more earned than the capital locked that epoch;
 *       §3e the econ band's decimal_unit refusal; §3f a commission
 *       increase submitted in a boundary block is first paid two
 *       boundaries after its activation, from a copy a delegator who left
 *       in reaction is no longer in (P3 fix round, H + 2E), a mid-epoch
 *       one activates at the first boundary >= its stored height, and the
 *       old H + E writer is reproduced charging the leaver. The rev-1 cases
 *       (min() rule, flash delegation, departed delegator, top-up keeps
 *       its copy amount, leave-and-return) are DELETED with the rule
 *       they pinned — see the note where they stood.
 *   §4  BAR MISS — a member that fails the shared participation
 *       predicate forfeits its WHOLE share, delegators included (engine).
 *   §5  PAYDAY — pays only on multiples of the interval, pays every
 *       accrual row to its owner (including a delegator that already
 *       left), empties the table, keeps the equation (direct call — the
 *       fixture lane's interval is 24 epochs, see §5's own note); the
 *       interval reader's three answers.
 *   §6  FAULT STAGES — F55/F56 (distribution) and F59 (balance copy)
 *       through the engine with a whole-DB digest, clean retry commits;
 *       the payday's two stages through its own callback.
 *   §7  DETERMINISM TWIN — two fixtures seeded in OPPOSITE order agree
 *       on the SYSTEM and CORE roots after a paying boundary and after a
 *       payday.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * Compile flags: none beyond a default build (DNAC_EPOCH_LENGTH 720 — the
 * cases drive up to 4E = 2880 zero-envelope blocks; §3f to 5E = 3600).
 * Environment: none.
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * One /tmp/test_v2_econ_<tag>_XXXXXX directory per fixture, removed at
 * close; a case that aborts through CHECK leaves its directory behind.
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. §5 calls the payday DIRECTLY, not through a block: the fixture
 *     chain's payout interval (24 epochs, its seeded genesis document's
 *     default) is out of reach; the harness scenario
 *     test_v2_rewards.sh covers the payday
 *     end to end (interval 2). §3b's mid-epoch withdrawal and §3's
 *     source-copy swap are written BY HAND between blocks (the fixture
 *     lane cannot sign an UNDELEGATE envelope): the withdrawal moves the
 *     live tables the way the runtime's UNDELEGATE + SYSFUND legs do
 *     (its release lock is pinned in test_v2_native.c §13b, not here),
 *     and the swap edits a table that is out of every root. §3c's
 *     withdrawal + top-up are by hand too, and can only land right
 *     before a BOUNDARY block (the next block must declare SYSTEM and
 *     CORE touched), so its "mid-epoch" moves sit in the epoch's last
 *     block; its release row is written locked by hand, not by the
 *     runtime.
 *  2. The expected numbers are hand-derived from the design formula (and
 *     re-derived in-test with 128-bit arithmetic); a design error shared
 *     by both would agree with itself.
 *
 * Copyright (c) 2026 nocdem — SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_emission.h"   /* DNAC_DECIMAL_UNIT      */
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_econ.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "witness/nodus_witness_v2_gen.h"     /* the payout default      */
#include "witness/nodus_witness_v2_schema.h"  /* migrate_v2s9            */
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_delegation.h"
#include "witness/nodus_witness_vset.h"
#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_types.h"
#include "dnac/dnac.h"
#include "dnac/cmt_pb.h"        /* CMT_PB_BLOCK_ID_FLAG_COMMIT             */
#include "dnac/ledger_ids.h"
#include "dnac/validator.h"
#include "dnac/vset_wire.h"     /* dna_vset_snapshot_t, dna_vset_free      */
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_fingerprint.h"
#include "crypto/utils/qgp_u128.h"

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "v2_genesis_fixture.h"

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", \
                __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

#define E ((uint64_t)DNAC_EPOCH_LENGTH)

/* ── deterministic pseudo-keys (the test_v2_epoch.c shape) ───────────
 * No real Dilithium keypair is needed: every block driven here carries
 * ZERO envelopes, so no signature is ever verified. */
#define N_KEYS 10
static uint8_t g_pk[N_KEYS][DNAC_PUBKEY_SIZE];
static uint8_t g_fpraw[N_KEYS][64];
static char    g_fp[N_KEYS][129];

static void keys_init(void) {
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < N_KEYS; i++) {
        for (int b = 0; b < DNAC_PUBKEY_SIZE; b++)
            g_pk[i][b] = (uint8_t)((b * 31u + i * 7u + 11u) & 0xFF);
        g_pk[i][0] = (uint8_t)(0x10 + i);
        qgp_sha3_512(g_pk[i], DNAC_PUBKEY_SIZE, g_fpraw[i]);
        for (int b = 0; b < 64; b++) {
            g_fp[i][2 * b]     = hexd[g_fpraw[i][b] >> 4];
            g_fp[i][2 * b + 1] = hexd[g_fpraw[i][b] & 0xF];
        }
        g_fp[i][128] = '\0';
    }
}

/* ── fixture ─────────────────────────────────────────────────────────── */

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
    uint8_t          chain_id[DNA_CHAIN_ID_LEN];
    uint64_t         height;
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

/* The height operand FORMATTED from the E macro, never a literal: the
 * epoch length is #ifndef-guarded (test_v2_epoch.c's own rule). */
static uint64_t q1f(nodus_witness_t *w, const char *fmt, uint64_t a) {
    char sql[320];
    snprintf(sql, sizeof(sql), fmt, (unsigned long long)a);
    return q1(w, sql);
}

/* The accrual of one owner (0 when it has no row). */
static uint64_t accrual_of(nodus_witness_t *w, int key) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT amount FROM v2_reward_accrual WHERE owner_fp = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return UINT64_MAX;
    sqlite3_bind_blob(st, 1, g_fpraw[key], 64, SQLITE_TRANSIENT);
    uint64_t v = 0;
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) v = (uint64_t)sqlite3_column_int64(st, 0);
    else if (rc != SQLITE_DONE) v = UINT64_MAX;
    sqlite3_finalize(st);
    return v;
}

/* The copy amount of (epoch, validator key, owner key); UINT64_MAX when
 * absent. */
static uint64_t copy_of(nodus_witness_t *w, uint64_t epoch, int vkey,
                        int okey) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT amount FROM v2_balance_copy WHERE epoch_start = ?1 "
            "AND validator_fp = ?2 AND owner_fp = ?3", -1, &st, NULL)
        != SQLITE_OK)
        return UINT64_MAX;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)epoch);
    sqlite3_bind_blob(st, 2, g_fpraw[vkey], 64, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 3, g_fpraw[okey], 64, SQLITE_TRANSIENT);
    uint64_t v = UINT64_MAX;
    if (sqlite3_step(st) == SQLITE_ROW)
        v = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

/* floor(a × b / d) with a 128-bit intermediate — the in-test re-derivation
 * of the formula (qgp_u128 is the shared arithmetic library, not the code
 * under test). */
static uint64_t mdiv(uint64_t a, uint64_t b, uint64_t d) {
    uint64_t rem = 0;
    return qgp_u128_div_u64(qgp_u128_mul_u64(qgp_u128_from_u64(a), b), d,
                            &rem).lo;
}

/* ── seeding ─────────────────────────────────────────────────────────── */

typedef struct {
    int      key;
    uint64_t bond;
    uint8_t  status;
    uint16_t comm;
} vspec_t;

typedef struct {
    int      delegator_key;
    int      validator_key;
    uint64_t amount;
} dspec_t;

#define BOND_BASE DNAC_SELF_STAKE_AMOUNT          /* 10M NODUS = 1e15 raw */
#define UTXO_A    5000000ULL
/* The reward reserve every fixture seeds: payout = POOL >> 16 is exactly
 * 1 000 000 raw, and the 12 345 below 2^16 is a remainder the payout
 * leaves in the pool by construction. */
#define POOL      (65536ULL * 1000000ULL + 12345ULL)
#define PAYOUT    1000000ULL

static int seed_validator(fixture_t *fx, const vspec_t *s,
                          uint64_t delegated) {
    dnac_validator_record_t v;
    memset(&v, 0, sizeof(v));
    memcpy(v.pubkey, g_pk[s->key], DNAC_PUBKEY_SIZE);
    v.self_stake         = s->bond;
    v.status             = s->status;
    v.active_since_block = 1;
    v.commission_bps     = s->comm;
    v.total_delegated    = delegated;
    v.external_delegated = delegated;
    memcpy(v.unstake_destination_fp, g_fp[s->key], 129);
    return nodus_validator_insert(fx->w, &v);
}

static int seed_utxo(fixture_t *fx, int k, uint64_t amount,
                     uint8_t seed_byte) {
    uint8_t seed[32], nul[64], pre[160];
    memset(seed, seed_byte, sizeof(seed));
    memcpy(pre, g_fp[k], 128);
    memcpy(pre + 128, seed, 32);
    if (qgp_sha3_512(pre, sizeof(pre), nul) != 0) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(fx->w->db,
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
            "tx_hash, output_index, block_height, created_at, "
            "unlock_block, domain_id) VALUES "
            "(?1, ?2, ?3, zeroblob(64), zeroblob(64), 0, 0, 0, 0, 1)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, nul, 64, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, g_fp[k], 128, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)amount);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* Stage 1: DB + schema + consensus-table seed (validators, delegations,
 * the supply row WITH the reward reserve, one UTXO) + the genesis vset
 * snapshots. Stops BEFORE the V2 genesis so the engine genesis writes
 * copy(0) over exactly these rows.
 *
 * tokenomics-v3 P4: the two stages ARE the seeded version-3 genesis
 * (v2_genesis_fixture.h): stage 1 opens with v2x_seed_prepare (live
 * rung S16, v2_successor, the econ band committed at effective 0 with
 * this build's values), stage 2 is v2x_seed_genesis (registry, the
 * engine genesis nodus_witness_v2_genesis_cmt, the stored document, the
 * reopen through the production open path). Every block then goes
 * through the cometbft lane with the test as the host (v2x_cmt_apply),
 * whose Comet block-store record per block is what the boundary's
 * committee seed reads at the lookback height (committee.c
 * v2_seed_block_id) — the legacy `blocks` row this fixture used to
 * plant is gone with the lane that read it. */
static int fx_stage1(fixture_t *fx, const char *tag,
                     const vspec_t *specs, size_t n_spec,
                     const dspec_t *dels, size_t n_del) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    /* the live constructor's cache sentinel (nodus_witness.c) — a zeroed
     * struct would read as a CACHED EMPTY committee for epoch 0 */
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_econ_%s_XXXXXX", tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain_id16, 0x4E, sizeof(fx->chain_id16));
    if (v2x_seed_prepare(fx->w, fx->chain_id16, 0) != 0) return -1;

    uint64_t bonds = 0, delegated_total = 0;
    for (size_t i = 0; i < n_spec; i++) {
        uint64_t del = 0;
        for (size_t j = 0; j < n_del; j++)
            if (dels[j].validator_key == specs[i].key)
                del += dels[j].amount;
        if (seed_validator(fx, &specs[i], del) != 0) return -1;
        bonds += specs[i].bond;
        delegated_total += del;
    }
    for (size_t j = 0; j < n_del; j++) {
        dnac_delegation_record_t d;
        memset(&d, 0, sizeof(d));
        memcpy(d.delegator_pubkey, g_pk[dels[j].delegator_key],
               DNAC_PUBKEY_SIZE);
        memcpy(d.validator_pubkey, g_pk[dels[j].validator_key],
               DNAC_PUBKEY_SIZE);
        d.amount = dels[j].amount;
        /* These rows stand for delegations bonded AT genesis: they are in
         * the genesis snapshots (nodus_witness_vset_commit_genesis below)
         * and in copy(0), which the engine genesis writes from them. The
         * distribution does not read delegated_at_block (design §7.1
         * "Silinenler"); 0 = bonded at genesis. (A real version-3 genesis
         * carries no delegations at all, nodus_witness_v2_gen.c; this is
         * fixture state.) */
        d.delegated_at_block = 0;
        if (nodus_delegation_insert(fx->w, &d) != 0) return -1;
    }
    {
        char sql[128];
        snprintf(sql, sizeof(sql),
                 "UPDATE validator_stats SET value = %d "
                 "WHERE key = 'active_count'", (int)n_spec);
        if (run_sql(fx->w->db, sql) != 0) return -1;
    }
    /* genesis == Σ CORE utxo + Σ self_stake + Σ delegated + reward_pool —
     * the exact RHS the CORE invariant sums at genesis (no accrual yet,
     * nodus_witness_v2_claims.c nodus_rt_core_invariant). */
    {
        uint64_t supply = UTXO_A + bonds + delegated_total + POOL;
        char sql[400];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO supply_tracking (id, genesis_supply, "
                 "total_burned, total_minted, current_supply, "
                 "last_tx_hash, last_sequence, reward_pool) VALUES (1, "
                 "%llu, 0, 0, %llu, zeroblob(64), 0, %llu)",
                 (unsigned long long)supply, (unsigned long long)supply,
                 (unsigned long long)POOL);
        if (run_sql(fx->w->db, sql) != 0) return -1;
    }
    if (seed_utxo(fx, 0, UTXO_A, 0xA1) != 0) return -1;
    if (nodus_witness_vset_commit_genesis(fx->w, 1) != 0) return -1;
    return 0;
}

static int fx_stage2(fixture_t *fx) {
    /* not a real genesis: stage 1 seeds a spendable UTXO_A row (and
     * genesis delegations and a reward pool, which the derivation's
     * post-conditions do not name) */
    v2x_seed_not_real(V2X_SEED_NOT_REAL_UTXOS);
    if (v2x_seed_genesis(fx->w, fx->chain_id16, 0, NULL, 0, NULL) != 0)
        return -1;
    if (nodus_witness_v2_chain_id(fx->w, fx->chain_id) != 0) return -1;
    fx->height = 0;
    return 0;
}

static void fx_close(fixture_t *fx) {
    if (fx->w) {
        if (fx->w->db) sqlite3_close(fx->w->db);
        free(fx->w);
        fx->w = NULL;
    }
    rmrf(fx->dir);
}

/* Apply one zero-envelope block at the next height whose decided last
 * commit carries a COMMIT vote from every key in `voter_mask` (bit i =
 * key i) — the real attendance writer's input, exactly as the app copies
 * it from an ABCI request (nodus_witness_v2_attendance_credit). Height 1
 * carries no previous commit (execution.go's precondition). */
/* the last block fx_block_mask handed the engine — read back only for
 * its out_reason (the refusal class the body labelled it with) */
static nodus_v2_block_t g_last_block;

static int fx_block_mask(fixture_t *fx, unsigned voter_mask,
                         nodus_v2_apply_fail_t fail_at, int *rc_out) {
    uint64_t h = fx->height + 1;
    nodus_v2_block_t b;
    memset(&b, 0, sizeof(b));
    b.global_height = h;
    b.epoch   = nodus_v2_epoch_for_height(h);
    b.envs    = NULL;
    b.n_envs  = 0;
    b.fail_at = fail_at;
    uint8_t addrs[N_KEYS][32];
    int32_t flags[N_KEYS];
    size_t  n = 0;
    if (h > 1) {
        for (int k = 0; k < N_KEYS; k++) {
            if (!(voter_mask & (1u << k))) continue;
            memcpy(addrs[n], g_fpraw[k], 32);
            flags[n] = CMT_PB_BLOCK_ID_FLAG_COMMIT;
            n++;
        }
        if (n > 0) {
            b.cmt.votes_address = (const uint8_t (*)[32])addrs;
            b.cmt.votes_block_id_flag = flags;
            b.cmt.votes_len = n;
        }
    }
    /* the cometbft lane, the test as the host: 0 committed,
     * NODUS_V2_INTERNAL_FAULT rolled back */
    int rc = v2x_cmt_apply(fx->w, &b);
    if (rc_out) *rc_out = rc;
    g_last_block = b;                  /* the refusal class + reason     */
    if (rc == 0) fx->height = h;
    if (rc != 0 && fail_at == V2AP_FAIL_NONE)
        fprintf(stderr, "block %llu rejected (rc=%d): %s\n",
                (unsigned long long)h, rc, b.out_reason);
    return rc == 0 ? 0 : -1;
}

static int fx_drive(fixture_t *fx, uint64_t target, unsigned voter_mask) {
    while (fx->height < target)
        if (fx_block_mask(fx, voter_mask, V2AP_FAIL_NONE, NULL) != 0)
            return -1;
    return 0;
}

/* Apply the next block with `pt` injected and prove the whole-database
 * digest did not move (the rollback-by-digest discipline, approved
 * record atlas-dec-d320daa10a8ccb455ec38ea0010b0c4b). */
static int fx_block_inject(fixture_t *fx, unsigned voter_mask,
                           nodus_v2_apply_fail_t pt, int *rc_out) {
    uint8_t d0[64], d1[64];
    if (fx->height + 1 == 0) return -1;
    if (v2x_db_digest(fx->w, d0) != 0) return -1;
    int rc = 0;
    (void)fx_block_mask(fx, voter_mask, pt, &rc);
    if (rc_out) *rc_out = rc;
    /* every boundary-stage failure is a node FAULT in the cometbft lane
     * (the wrapper folds every body return into it) */
    if (rc != NODUS_V2_INTERNAL_FAULT) return -1;   /* did not fire */
    /* and the body labelled it a boundary NODE FAULT (phase 6e), never
     * a verdict — the class the fold would otherwise hide */
    if (v2x_reason_is(&g_last_block, V2X_FAULT, "phase 6e") != 0)
        return -1;
    if (v2x_db_digest(fx->w, d1) != 0) return -1;
    return memcmp(d0, d1, 64) == 0 ? 0 : -1;
}

/* §0 — the conservation equation, recomputed TERM BY TERM from the
 * tables (design §7 P2-2):
 *   genesis + minted − burned
 *     == utxo + bonds + delegated + reward_pool + accrued (+ unclaimed
 *        + shielded, both 0 on these fixtures)
 * and checked against the engine's own gate SEPARATELY, so a mutation
 * that breaks the gate helper still shows up as the two disagreeing. */
typedef struct {
    uint64_t genesis, minted, burned;
    uint64_t utxo, bonds, delegated, pool, accrued;
} supply_terms_t;

static int supply_terms(nodus_witness_t *w, supply_terms_t *t) {
    memset(t, 0, sizeof(*t));
    nodus_witness_supply_t s;
    memset(&s, 0, sizeof(s));
    if (nodus_witness_supply_get(w, &s) != 0) return -1;
    t->genesis   = s.genesis_supply;
    t->minted    = s.total_minted;
    t->burned    = s.total_burned;
    t->pool      = s.reward_pool;
    t->utxo      = q1(w, "SELECT COALESCE(SUM(amount),0) FROM utxo_set");
    t->bonds     = q1(w, "SELECT COALESCE(SUM(self_stake),0) "
                         "FROM validators");
    t->delegated = q1(w, "SELECT COALESCE(SUM(total_delegated),0) "
                         "FROM validators");
    t->accrued   = q1(w, "SELECT COALESCE(SUM(amount),0) "
                         "FROM v2_reward_accrual");
    return 0;
}

static int supply_closes(nodus_witness_t *w) {
    supply_terms_t t;
    if (supply_terms(w, &t) != 0) return 0;
    return t.genesis + t.minted - t.burned ==
           t.utxo + t.bonds + t.delegated + t.pool + t.accrued &&
           t.minted == 0 &&
           nodus_witness_v2_supply_check(w) == 0;
}

/* ── the compositions ──────────────────────────────────────────────── */

/* Three ACTIVE validators; key 0 carries two delegators (keys 5 and 6)
 * and a 10% commission. Powers (total_stake / 1e8): 1.4e7, 1e7, 1e7. */
static const vspec_t SPECD[3] = {
    { 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 1000 },
    { 1, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 0 },
    { 2, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 0 },
};
static const vspec_t SPECD_REV[3] = {
    { 2, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 0 },
    { 1, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 0 },
    { 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 1000 },
};
#define D5_AMT  (300000000000000ULL)   /* 3M NODUS */
#define D6_AMT  (100000000000000ULL)   /* 1M NODUS */
static const dspec_t DELS[2] = {
    { 5, 0, D5_AMT },
    { 6, 0, D6_AMT },
};
static const dspec_t DELS_REV[2] = {
    { 6, 0, D6_AMT },
    { 5, 0, D5_AMT },
};
#define ALL3 ((1u << 0) | (1u << 1) | (1u << 2))

/* The hand-derived expectations for SPECD at the first boundary with
 * every member attending (the governing snapshot(0) and the source
 * copy(0) both come from the seeded rows):
 *   power   total_stake / 1e8: 1.4e7, 1e7, 1e7 — Σ 3.4e7
 *   shares  floor(1e6 × 14/34) = 411764, floor(1e6 × 10/34) = 294117
 *           (×2)                           (Σ 999998, outer rest 2)
 *   key 0:  base = floor(411764 × self_bond 1e15 / total 1.4e15) =
 *           floor(411764 × 5/7) = 294117, gross 117647, commission
 *           floor(117647 / 10) = 11764, net 105883
 *           → key 0 accrues 294117 + 11764 = 305881,
 *             key 5 floor(105883 × 3/4) = 79412,
 *             key 6 floor(105883 × 1/4) = 26470        (inner rest 1)
 *   Σ credited 305881 + 79412 + 26470 + 2 × 294117 = 999997; the pool
 *   keeps POOL − 999997. */
#define EXP_V0   305881ULL
#define EXP_V12  294117ULL
#define EXP_D5   79412ULL
#define EXP_D6   26470ULL
#define EXP_SUM  999997ULL

/* The design §7.1 "P2-6 rev 2" formula for the SPECD composition, in
 * 128-bit arithmetic — the in-test re-derivation every hand constant
 * below is checked against (FIXTURE GUARD). Key 0's delegators are key 5
 * and key 6 with source-copy amounts a5 / a6 (either may be 0); key 0's
 * governing total_stake is BOND_BASE + a5 + a6 (the consistency gate
 * makes the snapshot entry and the copy agree on that sum); keys 1 and
 * 2 carry BOND_BASE alone. Every member attends. */
typedef struct {
    uint64_t v0, v12, d5, d6, sum;
} split_t;

static void split_specd(uint64_t payout, uint64_t a5, uint64_t a6,
                        split_t *o) {
    const uint64_t t0 = BOND_BASE + a5 + a6;
    const uint64_t p0 = t0 / (uint64_t)DNAC_DECIMAL_UNIT;
    const uint64_t p1 = BOND_BASE / (uint64_t)DNAC_DECIMAL_UNIT;
    const uint64_t sp = p0 + 2 * p1;
    const uint64_t s0 = mdiv(payout, p0, sp);
    const uint64_t s1 = mdiv(payout, p1, sp);
    const uint64_t base = mdiv(s0, BOND_BASE, t0);
    const uint64_t gross = s0 - base;
    const uint64_t com = mdiv(gross, 1000, 10000);  /* SPECD key 0: 10% */
    const uint64_t net = gross - com;
    o->v0  = base + com;
    o->v12 = s1;
    o->d5  = (a5 + a6) ? mdiv(net, a5, a5 + a6) : 0;
    o->d6  = (a5 + a6) ? mdiv(net, a6, a5 + a6) : 0;
    o->sum = o->v0 + 2 * o->v12 + o->d5 + o->d6;
}

/* ══════════════════════════════════════════════════════════════════════
 * §1 THE BALANCE COPY (P2-5)
 * ════════════════════════════════════════════════════════════════════ */

/* RED ON THE PRE-P2 TREE: the table and its writer do not exist.
 * KILLED BY: dropping the engine-genesis copy(0) write; keying the copy
 * by delegation-row hash instead of the raw fp; writing a zero-bond
 * validator; not pruning below H−2E (P3-2 — was H−E). */
static int t_balance_copy(void) {
    fixture_t fx;
    CHECK(fx_stage1(&fx, "copy", SPECD, 3, DELS, 2) == 0, "stage1");
    CHECK(fx_stage2(&fx) == 0, "stage2");

    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_balance_copy "
                   "WHERE epoch_start = 0") == 5,
          "copy(0): three bonds + two delegations");
    CHECK(copy_of(fx.w, 0, 0, 0) == BOND_BASE &&
          copy_of(fx.w, 0, 1, 1) == BOND_BASE &&
          copy_of(fx.w, 0, 2, 2) == BOND_BASE,
          "each bond under (validator, owner = the validator)");
    CHECK(copy_of(fx.w, 0, 0, 5) == D5_AMT &&
          copy_of(fx.w, 0, 0, 6) == D6_AMT,
          "each delegation under (validator, owner = the delegator), raw "
          "SHA3-512(pubkey) keyed");
    OK();

    /* the copy is OUT of every root: rewriting it moves neither root */
    {
        uint8_t s0[64], c0[64], s1[64], c1[64];
        CHECK(nodus_witness_system_root_v2(fx.w, s0) == 0 &&
              nodus_witness_core_root_v2(fx.w, c0) == 0, "roots pre");
        CHECK(run_sql(fx.w->db, "UPDATE v2_balance_copy SET amount = "
                                "amount + 1 WHERE epoch_start = 0") == 0,
              "poke the copy");
        CHECK(nodus_witness_system_root_v2(fx.w, s1) == 0 &&
              nodus_witness_core_root_v2(fx.w, c1) == 0, "roots post");
        CHECK(memcmp(s0, s1, 64) == 0 && memcmp(c0, c1, 64) == 0,
              "the balance copy reaches no root");
        CHECK(run_sql(fx.w->db, "UPDATE v2_balance_copy SET amount = "
                                "amount - 1 WHERE epoch_start = 0") == 0,
              "restore the copy");
    }
    OK();

    /* RETENTION, tokenomics-v3 P3-2: boundary B keeps copy(B−2E),
     * copy(B−E) and copy(B) — three copies (P2 kept two). By hand:
     *   E:  copy(0), copy(E)            (nothing below E−2E to prune)
     *   2E: copy(0), copy(E), copy(2E)  (prune below 0: nothing)
     *   3E: copy(E), copy(2E), copy(3E) (prune below E: copy(0) goes)
     * RED ON THE PRE-P3 TREE: boundary 2E pruned copy(0) (below 2E−E).
     * KILLED BY: keeping two copies (copy(H−3E) gone before the
     * distribution at H reads it); keeping none of the older. */
    CHECK(fx_drive(&fx, E, ALL3) == 0, "drive to E");
    CHECK(q1f(fx.w, "SELECT COUNT(*) FROM v2_balance_copy "
                    "WHERE epoch_start = %llu", E) == 5 &&
          q1(fx.w, "SELECT COUNT(*) FROM v2_balance_copy "
                   "WHERE epoch_start = 0") == 5,
          "at E: copy(E) written, copy(0) kept");
    OK();
    CHECK(fx_drive(&fx, 2 * E, ALL3) == 0, "drive to 2E");
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_balance_copy "
                   "WHERE epoch_start = 0") == 5 &&
          q1f(fx.w, "SELECT COUNT(*) FROM v2_balance_copy "
                    "WHERE epoch_start = %llu", E) == 5 &&
          q1f(fx.w, "SELECT COUNT(*) FROM v2_balance_copy "
                    "WHERE epoch_start = %llu", 2 * E) == 5,
          "at 2E: copy(0), copy(E) and copy(2E) all kept (P3-2)");
    OK();
    CHECK(fx_drive(&fx, 3 * E, ALL3) == 0, "drive to 3E");
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_balance_copy "
                   "WHERE epoch_start = 0") == 0 &&
          q1f(fx.w, "SELECT COUNT(*) FROM v2_balance_copy "
                    "WHERE epoch_start = %llu", E) == 5 &&
          q1f(fx.w, "SELECT COUNT(*) FROM v2_balance_copy "
                    "WHERE epoch_start = %llu", 2 * E) == 5 &&
          q1f(fx.w, "SELECT COUNT(*) FROM v2_balance_copy "
                    "WHERE epoch_start = %llu", 3 * E) == 5,
          "at 3E: copy(0) pruned — only copy(E), copy(2E), copy(3E)");
    OK();
    CHECK(supply_closes(fx.w), "the equation closes after three boundaries");
    OK();
    fx_close(&fx);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §2 DISTRIBUTION MATH, through the engine (P2-6)
 * ════════════════════════════════════════════════════════════════════ */

/* RED ON THE PRE-P2 TREE: the old settlement paid the WHOLE (empty,
 * since nothing minted) epoch pool per seat as UTXOs and burned the
 * rest; supply_tracking had no reward_pool and v2_reward_accrual did not
 * exist.
 * KILLED BY: an equal-per-seat share; a 64-bit inner product (it
 * overflows at these magnitudes, 2^64 ≈ 1.8e19: share × self_bond =
 * 411764 × 1e15 ≈ 4.1e20); burning or keeping the remainders anywhere but
 * the pool; a pool debit of the payout instead of Σ credited. */
static int t_distribution_math(void) {
    fixture_t fx;
    CHECK(fx_stage1(&fx, "math", SPECD, 3, DELS, 2) == 0, "stage1");
    CHECK(fx_stage2(&fx) == 0, "stage2");
    CHECK(supply_closes(fx.w), "the equation closes at genesis");
    OK();

    CHECK(fx_drive(&fx, E - 1, ALL3) == 0, "drive to E-1");
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_reward_accrual") == 0 &&
          q1(fx.w, "SELECT reward_pool FROM supply_tracking") == POOL,
          "nothing accrues between boundaries");
    CHECK(supply_closes(fx.w), "the equation closes mid-epoch");
    OK();

    /* the in-test re-derivation of the hand-derived constants (the
     * governing snapshot(0) and the source copy(0) are the seeded rows) */
    {
        CHECK((POOL >> 16) == PAYOUT, "payout = pool >> 16");
        split_t s;
        split_specd(PAYOUT, D5_AMT, D6_AMT, &s);
        CHECK(s.v0 == EXP_V0 && s.v12 == EXP_V12 && s.d5 == EXP_D5 &&
              s.d6 == EXP_D6 && s.sum == EXP_SUM,
              "FIXTURE GUARD: the constants match the formula");
    }
    OK();

    uint8_t core_pre[64];
    CHECK(nodus_witness_core_root_v2(fx.w, core_pre) == 0, "core pre");
    CHECK(fx_drive(&fx, E, ALL3) == 0,
          "boundary E applies (CORE declared touched — the engine "
          "rejects an undeclared mutation)");
    CHECK(accrual_of(fx.w, 0) == EXP_V0 &&
          accrual_of(fx.w, 1) == EXP_V12 &&
          accrual_of(fx.w, 2) == EXP_V12,
          "validators: base + commission (key 0), full share (keys 1, 2)");
    CHECK(accrual_of(fx.w, 5) == EXP_D5 && accrual_of(fx.w, 6) == EXP_D6,
          "delegators: net ∝ effective amount");
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_reward_accrual") == 5,
          "exactly five recipients");
    CHECK(q1(fx.w, "SELECT reward_pool FROM supply_tracking")
              == POOL - EXP_SUM,
          "the pool is debited by EXACTLY Σ credited — the 12345 below "
          "2^16, the outer rest 2 and the inner rest 1 all stay");
    CHECK(q1(fx.w, "SELECT total_burned FROM supply_tracking") == 0,
          "NOTHING is burned");
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM utxo_set") == 1,
          "and nothing is paid as a UTXO at a non-payday boundary");
    OK();
    {
        uint8_t core_post[64];
        CHECK(nodus_witness_core_root_v2(fx.w, core_post) == 0 &&
              memcmp(core_pre, core_post, 64) != 0,
              "the CORE root moved (accrual_root + supply leaf)");
    }
    CHECK(supply_closes(fx.w),
          "the equation closes after the paying boundary");
    OK();

    /* the second boundary pays out of what is LEFT (pool >> 16 again) */
    {
        const uint64_t pool1 = POOL - EXP_SUM;
        const uint64_t p2 = pool1 >> 16;
        CHECK(fx_drive(&fx, 2 * E, ALL3) == 0, "drive to 2E");
        const uint64_t pool2 =
            q1(fx.w, "SELECT reward_pool FROM supply_tracking");
        CHECK(pool2 < pool1 && pool1 - pool2 <= p2,
              "the 2E payout is at most (pool after E) >> 16");
        CHECK(accrual_of(fx.w, 1) > EXP_V12,
              "and accrues ON TOP of the unpaid E accrual");
        CHECK(supply_closes(fx.w), "the equation closes after 2E");
    }
    OK();
    fx_close(&fx);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §3 REVISION 2 — the SOURCE copy src(H) (design §7.1 "P2-6 rev 2")
 * ════════════════════════════════════════════════════════════════════ */

/* ── DELETED rev-1 cases, and why ────────────────────────────────────
 * t_min_rule, t_flash_delegation, t_departed_delegator,
 * t_topup_keeps_copy and t_leave_and_return pinned the rev-1 rule —
 * min(copy(H−E), live at H) per stake, and 0 for a delegation whose
 * delegated_at_block was after H−E (decision file §3 2026-09-24 entries
 * (1) and (2)). Revision 2 deletes that rule (design §7.1 "Silinenler";
 * the decision's "DELEGATOR = VALIDATOR GİBİ" entry supersedes (1)'s
 * min() and (2)): the distribution now pays the GOVERNING snapshot by
 * its own power and splits inside a member by the source copy, and the
 * flash / leave-and-return / withdraw-use-return levers are closed by
 * the UNDELEGATE release lock instead (test_v2_native.c §13b). Each old
 * expectation is now simply wrong — a mid-epoch leaver IS paid (§3b), a
 * flash delegation into the governing set IS paid and is locked — and
 * the fixture shape t_flash_delegation built (the snapshot frozen, then
 * the stake moved, then copy(0) taken) is exactly a snapshot/copy
 * disagreement, which §3a now proves FAULTS. nodus_delegation_update,
 * used only by these cases, is deleted with them. */

/* Set one copy row's amount by hand (the table is out of every root). */
static int copy_set(nodus_witness_t *w, uint64_t epoch, int vkey, int okey,
                    uint64_t amount) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "UPDATE v2_balance_copy SET amount = ?1 WHERE epoch_start = ?2 "
            "AND validator_fp = ?3 AND owner_fp = ?4", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)amount);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)epoch);
    sqlite3_bind_blob(st, 3, g_fpraw[vkey], 64, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 4, g_fpraw[okey], 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return (rc == SQLITE_DONE && sqlite3_changes(w->db) == 1) ? 0 : -1;
}

/* The hand-derived boundaries 2E and 3E of SPECD with every member
 * attending (the §2 composition carried on):
 *   pool after E  = POOL − 999997 = 65 536 012 345 − 999 997
 *                 = 65 535 012 348
 *   payout(2E)    = floor(65 535 012 348 / 65 536) = 999 984
 *                   (65 536 × 999 984 = 65 534 951 424, rest 60 924)
 *   power 1.4e7 / 1e7 / 1e7 (Σ 3.4e7)
 *   share0 = floor(999984 × 14/34) = floor(13 999 776 / 34) = 411 758
 *   share1 = share2 = floor(9 999 840 / 34) = 294 112
 *   base0  = floor(411758 × 5/7) = floor(2 058 790 / 7) = 294 112
 *   gross 117 646, commission 11 764, net 105 882
 *   → key 0 += 305 876; the 3/4 delegator += floor(317 646 / 4) = 79 411,
 *     the 1/4 delegator += floor(105 882 / 4) = 26 470;
 *     Σ 305 876 + 79 411 + 26 470 + 2 × 294 112 = 999 981
 *   pool after 2E = 65 535 012 348 − 999 981 = 65 534 012 367
 *   payout(3E)    = floor(65 534 012 367 / 65 536) = 999 969
 *                   (65 536 × 999 969 = 65 533 968 384, rest 43 983)
 *   share0 = floor(999969 × 14/34) = floor(13 999 566 / 34) = 411 751
 *   share1 = share2 = floor(9 999 690 / 34) = 294 108
 *   base0  = floor(411751 × 5/7) = floor(2 058 755 / 7) = 294 107
 *   gross 117 644, commission 11 764, net 105 880
 *   → key 0 += 305 871; the 1/4 delegator += 26 470, the 3/4 delegator
 *     += floor(317 640 / 4) = 79 410; Σ 305 871 + 26 470 + 79 410 +
 *     2 × 294 108 = 999 967 */
#define SC_POOL1    (POOL - EXP_SUM)
#define SC_PAYOUT2  999984ULL
#define SC_V0_2     305876ULL
#define SC_V12_2    294112ULL
#define SC_Q3_2     79411ULL     /* the 3/4 delegator at 2E */
#define SC_Q1_2     26470ULL     /* the 1/4 delegator at 2E */
#define SC_SUM2     999981ULL
#define SC_POOL2    (SC_POOL1 - SC_SUM2)
#define SC_PAYOUT3  999969ULL
#define SC_V0_3     305871ULL
#define SC_V12_3    294108ULL
#define SC_Q1_3     26470ULL     /* the 1/4 delegator at 3E */
#define SC_Q3_3     79410ULL     /* the 3/4 delegator at 3E */
#define SC_SUM3     999967ULL
/* tokenomics-v3 P3-2 — boundary 4E of SPECD, every member attending:
 *   pool after 3E = 65 534 012 367 − 999 967 = 65 533 012 400
 *   payout(4E)    = floor(65 533 012 400 / 65 536) = 999 954
 *                   (65 536 × 999 954 = 65 532 985 344, rest 27 056)
 *   share0 = floor(999954 × 14/34) = floor(13 999 356 / 34) = 411 745
 *   share1 = share2 = floor(9 999 540 / 34) = 294 104
 *   base0  = floor(411745 × 5/7) = floor(2 058 725 / 7) = 294 103
 *   gross 117 642, commission 11 764, net 105 878
 *   with the SWAPPED copy(E) (key 5 = 1e14, key 6 = 3e14):
 *   → key 0 += 305 867; key 5 (1/4) += floor(105 878 / 4) = 26 469,
 *     key 6 (3/4) += floor(317 634 / 4) = 79 408;
 *     Σ 305 867 + 26 469 + 79 408 + 2 × 294 104 = 999 952 */
#define SC_POOL3    (SC_POOL2 - SC_SUM3)
#define SC_PAYOUT4  999954ULL
#define SC_V0_4     305867ULL
#define SC_V12_4    294104ULL
#define SC_Q1_4     26469ULL     /* the 1/4 delegator at 4E */
#define SC_Q3_4     79408ULL     /* the 3/4 delegator at 4E */
#define SC_SUM4     999952ULL

/* Through the engine at E, 2E, 3E and 4E. Right after boundary E the
 * copy(E) amounts of keys 5 and 6 are SWAPPED by hand (5 → 1e14, 6 →
 * 3e14; the sum and the self row untouched). tokenomics-v3 P3-2: the
 * distribution at H splits by src(H) = H − 3E (0 below 3E), the copy the
 * governing snapshot(H − E) was BUILT from under P3-1's "okuma B":
 *   E:  src 0 → copy(0), 3:1 → the §2 numbers.
 *   2E: src 0 → copy(0), still 3:1 → key 5 += 79 411, key 6 += 26 470.
 *   3E: src 0 → copy(0) AGAIN (snapshot(2E) was built at E from copy(0)),
 *       3:1 → key 5 += 79 410, key 6 += 26 470 (the swapped copy(E) is
 *       NOT read yet). The snapshot(3E) commit_next(2E) stored was built
 *       from the swapped copy(E) — same sum, so the gate holds at 4E.
 *   4E: src = E → the swapped copy(E), 1:3 → key 5 += 26 469, key 6 +=
 *       79 408 (copy(2E) and copy(3E), written from the unswapped live
 *       rows, are NOT read).
 * Retention on the way: copy(0) still exists when 3E runs (P3-2 keeps
 * three), copy(E) when 4E runs, and copy(0) is gone after 3E.
 * RED ON THE PRE-P3 TREE: src(3E) was E (H − 2E) — the swapped copy(E)
 * split 3E 1:3 (key 5 += 26 470), and boundary 2E had already pruned
 * copy(0).
 * KILLED BY: src(H) = H − 2E or H − E; pruning copy(H − 3E) before the
 * distribution; a src that is not 0 below 3E. */
static int t_source_copy(void) {
    fixture_t fx;
    CHECK(fx_stage1(&fx, "srccopy", SPECD, 3, DELS, 2) == 0, "stage1");
    CHECK(fx_stage2(&fx) == 0, "stage2");
    {
        split_t s2, s3, s4;
        split_specd(SC_PAYOUT2, D5_AMT, D6_AMT, &s2);
        split_specd(SC_PAYOUT3, D5_AMT, D6_AMT, &s3);   /* copy(0) again */
        split_specd(SC_PAYOUT4, D6_AMT, D5_AMT, &s4);   /* swapped copy */
        CHECK((SC_POOL1 >> 16) == SC_PAYOUT2 &&
              (SC_POOL2 >> 16) == SC_PAYOUT3 &&
              (SC_POOL3 >> 16) == SC_PAYOUT4 &&
              s2.v0 == SC_V0_2 && s2.v12 == SC_V12_2 &&
              s2.d5 == SC_Q3_2 && s2.d6 == SC_Q1_2 && s2.sum == SC_SUM2 &&
              s3.v0 == SC_V0_3 && s3.v12 == SC_V12_3 &&
              s3.d5 == SC_Q3_3 && s3.d6 == SC_Q1_3 && s3.sum == SC_SUM3 &&
              s4.v0 == SC_V0_4 && s4.v12 == SC_V12_4 &&
              s4.d5 == SC_Q1_4 && s4.d6 == SC_Q3_4 && s4.sum == SC_SUM4,
              "FIXTURE GUARD: the hand constants match the formula");
    }
    OK();

    /* E — src = 0 */
    CHECK(fx_drive(&fx, E, ALL3) == 0, "drive to E");
    CHECK(accrual_of(fx.w, 0) == EXP_V0 && accrual_of(fx.w, 5) == EXP_D5 &&
          accrual_of(fx.w, 6) == EXP_D6 && accrual_of(fx.w, 1) == EXP_V12 &&
          accrual_of(fx.w, 2) == EXP_V12,
          "E: split by copy(0), the §2 numbers");
    OK();

    /* swap keys 5 and 6 in copy(E) — sum 4e14 and the self row kept */
    CHECK(copy_of(fx.w, E, 0, 5) == D5_AMT &&
          copy_of(fx.w, E, 0, 6) == D6_AMT, "copy(E) as written");
    CHECK(copy_set(fx.w, E, 0, 5, D6_AMT) == 0 &&
          copy_set(fx.w, E, 0, 6, D5_AMT) == 0, "swap copy(E)");
    OK();

    /* 2E — src = 0 */
    CHECK(fx_drive(&fx, 2 * E - 1, ALL3) == 0, "drive to 2E-1");
    CHECK(copy_of(fx.w, 0, 0, 5) == D5_AMT && copy_of(fx.w, 0, 0, 6) ==
              D6_AMT, "RETENTION: copy(0) still exists when 2E runs");
    CHECK(fx_drive(&fx, 2 * E, ALL3) == 0, "boundary 2E");
    CHECK(accrual_of(fx.w, 5) == EXP_D5 + SC_Q3_2 &&
          accrual_of(fx.w, 6) == EXP_D6 + SC_Q1_2,
          "2E: split by copy(0) = src(2E), NOT by the swapped copy(E)");
    CHECK(accrual_of(fx.w, 0) == EXP_V0 + SC_V0_2 &&
          accrual_of(fx.w, 1) == EXP_V12 + SC_V12_2 &&
          accrual_of(fx.w, 2) == EXP_V12 + SC_V12_2,
          "2E: the members by the governing snapshot(E)'s power");
    CHECK(q1(fx.w, "SELECT reward_pool FROM supply_tracking") == SC_POOL2,
          "2E: the pool debited by exactly Σ credited");
    OK();

    /* 3E — src = 0 (P3-2: H − 3E) */
    CHECK(fx_drive(&fx, 3 * E - 1, ALL3) == 0, "drive to 3E-1");
    CHECK(copy_of(fx.w, 0, 0, 5) == D5_AMT && copy_of(fx.w, E, 0, 5) ==
              D6_AMT,
          "RETENTION: copy(0) still exists when 3E runs (three copies "
          "kept), next to the swapped copy(E)");
    CHECK(fx_drive(&fx, 3 * E, ALL3) == 0, "boundary 3E");
    CHECK(accrual_of(fx.w, 5) == EXP_D5 + SC_Q3_2 + SC_Q3_3 &&
          accrual_of(fx.w, 6) == EXP_D6 + SC_Q1_2 + SC_Q1_3,
          "3E: split by copy(0) = src(3E), NOT by the swapped copy(E)");
    CHECK(accrual_of(fx.w, 0) == EXP_V0 + SC_V0_2 + SC_V0_3 &&
          accrual_of(fx.w, 1) == EXP_V12 + SC_V12_2 + SC_V12_3,
          "3E: the members by the governing snapshot(2E)'s power");
    CHECK(q1(fx.w, "SELECT reward_pool FROM supply_tracking") == SC_POOL3,
          "3E: the pool debited by exactly Σ credited");
    OK();

    /* 4E — src = E */
    CHECK(fx_drive(&fx, 4 * E - 1, ALL3) == 0, "drive to 4E-1");
    CHECK(copy_of(fx.w, E, 0, 5) == D6_AMT &&
          copy_of(fx.w, 0, 0, 5) == UINT64_MAX,
          "RETENTION: copy(E) (swapped) exists when 4E runs; copy(0) is "
          "gone (pruned by boundary 3E)");
    CHECK(fx_drive(&fx, 4 * E, ALL3) == 0, "boundary 4E");
    CHECK(accrual_of(fx.w, 5) == EXP_D5 + SC_Q3_2 + SC_Q3_3 + SC_Q1_4 &&
          accrual_of(fx.w, 6) == EXP_D6 + SC_Q1_2 + SC_Q1_3 + SC_Q3_4,
          "4E: split by the swapped copy(E) = src(4E), NOT by copy(2E) "
          "or copy(3E)");
    CHECK(accrual_of(fx.w, 0) == EXP_V0 + SC_V0_2 + SC_V0_3 + SC_V0_4 &&
          accrual_of(fx.w, 1) == EXP_V12 + SC_V12_2 + SC_V12_3 + SC_V12_4,
          "4E: the members by the governing snapshot(3E)'s power");
    CHECK(q1(fx.w, "SELECT reward_pool FROM supply_tracking") ==
              SC_POOL3 - SC_SUM4,
          "4E: the pool debited by exactly Σ credited");
    CHECK(supply_closes(fx.w), "the equation closes after 4E");
    OK();
    fx_close(&fx);
    return 0;
}

/* A FULL UNDELEGATE by hand, conserving: the row is deleted, both
 * validator totals fall by `amount`, and the principal comes back to the
 * delegator as a UTXO (the movement the runtime's UNDELEGATE + SYSFUND
 * legs make — minus the release lock, which does not reach any reward
 * table and is pinned in test_v2_native.c §13b; the same shape t_payday
 * uses inline). */
static int undelegate_by_hand(fixture_t *fx, int dkey, int vkey,
                              uint64_t amount, uint8_t seed_byte) {
    if (nodus_delegation_delete(fx->w, g_pk[dkey], g_pk[vkey]) != 0)
        return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(fx->w->db,
            "UPDATE validators SET total_delegated = total_delegated - ?1, "
            "external_delegated = external_delegated - ?1 "
            "WHERE pubkey = ?2", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)amount);
    sqlite3_bind_blob(st, 2, g_pk[vkey], DNAC_PUBKEY_SIZE, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE || sqlite3_changes(fx->w->db) != 1) return -1;
    return seed_utxo(fx, dkey, amount, seed_byte);
}

/* ══════════════════════════════════════════════════════════════════════
 * §3a THE CONSISTENCY GATE (design §7.1 "Tutarlılık kapısı") — engine
 * ════════════════════════════════════════════════════════════════════ */

/* At 2E−1 the source of the 2E distribution is copy(0) (src(2E) = 0) and
 * the governing snapshot is snapshot(E) — both from the seeded rows. One
 * source-copy row is tampered by +1 and boundary 2E is applied:
 *   (a) a DELEGATOR row (key 5 under key 0): Σ delegator rows 4e14 + 1
 *       ≠ total_stake − self_bond = 4e14;
 *   (b) the SELF row (key 0 under key 0): 1e15 + 1 ≠ self_bond 1e15;
 *   (c) a NEW row (key 7 under key 0, 1 raw) the snapshot never counted.
 * Each must FAULT the block (-2) and roll it back byte-identically — the
 * accrual table and the pool untouched. Restored, the same boundary
 * commits the §3 2E numbers.
 * RED ON THE PRE-REV2 TREE: there was no gate, and the rev-1 split read
 * copy(H−E) = copy(E), so a tampered copy(0) was not even read at 2E —
 * the block committed.
 * KILLED BY: dropping the gate or either of its two equalities; checking
 * a copy other than src(H); paying before the gate has seen every
 * member. */
static int t_consistency_gate(void) {
    fixture_t fx;
    CHECK(fx_stage1(&fx, "gate", SPECD, 3, DELS, 2) == 0, "stage1");
    CHECK(fx_stage2(&fx) == 0, "stage2");
    CHECK(fx_drive(&fx, 2 * E - 1, ALL3) == 0, "drive to 2E-1");
    const uint64_t pool0 = q1(fx.w, "SELECT reward_pool FROM supply_tracking");
    const uint64_t n_acc0 = q1(fx.w, "SELECT COUNT(*) FROM v2_reward_accrual");
    const uint64_t a0 = accrual_of(fx.w, 0);
    CHECK(pool0 == SC_POOL1 && n_acc0 == 5 && a0 == EXP_V0,
          "boundary E paid the §2 numbers");
    OK();

    int rc = 0;
    /* (a) a delegator row */
    CHECK(copy_set(fx.w, 0, 0, 5, D5_AMT + 1) == 0, "tamper key 5");
    CHECK(fx_block_inject(&fx, ALL3, V2AP_FAIL_NONE, &rc) == 0 && rc == -2,
          "(a) a delegator-row mismatch FAULTS the boundary, rolled back "
          "whole");
    CHECK(copy_set(fx.w, 0, 0, 5, D5_AMT) == 0, "restore key 5");
    OK();
    /* (b) the self row */
    CHECK(copy_set(fx.w, 0, 0, 0, BOND_BASE + 1) == 0, "tamper key 0");
    CHECK(fx_block_inject(&fx, ALL3, V2AP_FAIL_NONE, &rc) == 0 && rc == -2,
          "(b) a self-row mismatch FAULTS the boundary");
    CHECK(copy_set(fx.w, 0, 0, 0, BOND_BASE) == 0, "restore key 0");
    OK();
    /* (c) a row the snapshot never counted */
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
                  "INSERT INTO v2_balance_copy (epoch_start, validator_fp, "
                  "owner_fp, amount) VALUES (0, ?1, ?2, 1)",
                  -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_blob(st, 1, g_fpraw[0], 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 2, g_fpraw[7], 64, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "plant key 7");
        sqlite3_finalize(st);
    }
    CHECK(fx_block_inject(&fx, ALL3, V2AP_FAIL_NONE, &rc) == 0 && rc == -2,
          "(c) an extra copy row FAULTS the boundary");
    CHECK(run_sql(fx.w->db, "DELETE FROM v2_balance_copy WHERE amount = 1 "
                            "AND epoch_start = 0") == 0 &&
          copy_of(fx.w, 0, 0, 7) == UINT64_MAX, "remove key 7");
    OK();

    CHECK(q1(fx.w, "SELECT reward_pool FROM supply_tracking") == pool0 &&
          q1(fx.w, "SELECT COUNT(*) FROM v2_reward_accrual") == n_acc0 &&
          accrual_of(fx.w, 0) == a0,
          "after three faults the pool and the accruals are untouched");
    OK();
    CHECK(fx_block_mask(&fx, ALL3, V2AP_FAIL_NONE, NULL) == 0,
          "restored, boundary 2E commits");
    CHECK(accrual_of(fx.w, 0) == EXP_V0 + SC_V0_2 &&
          accrual_of(fx.w, 5) == EXP_D5 + SC_Q3_2 &&
          accrual_of(fx.w, 6) == EXP_D6 + SC_Q1_2 &&
          q1(fx.w, "SELECT reward_pool FROM supply_tracking") == SC_POOL2,
          "and pays the §3 2E numbers");
    CHECK(supply_closes(fx.w), "the equation closes");
    OK();
    fx_close(&fx);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §3b A MID-EPOCH WITHDRAWAL IS PAID until its stake leaves the voting
 * power (design §7.1; decision file §3 2026-09-24 "DELEGATOR = VALIDATOR
 * GİBİ" (a)) — engine
 * ════════════════════════════════════════════════════════════════════ */

/* Key 6 (1e14 to key 0) FULLY withdraws between blocks E−1 and E — the
 * state a withdrawal executed in block E−1 or E leaves (both run before
 * boundary E, so the stake is out of copy(E); L(h) = 3E for both under
 * tokenomics-v3 P3-2, nodus_v2_power_exit_boundary).
 *   E:  governing snapshot(0) and copy(0) both carry key 6 → the §2
 *       numbers, key 6 += 26 470 (EXP_D6).
 *   2E: governing snapshot(E) (genesis-built) and copy(0) still carry
 *       key 6 → the §3 2E numbers, key 6 += 26 470 (SC_Q1_2).
 *   3E: governing snapshot(2E) was built at E by "okuma B" from copy(0),
 *       WITH key 6, and src(3E) = copy(0) → still paid: the §3 3E numbers
 *       at 3:1, key 6 += 26 470 (SC_Q1_3), key 5 += 79 410 (SC_Q3_3).
 *   4E: governing snapshot(3E) was built at 2E from copy(E), WITHOUT key
 *       6, and src(4E) = E → key 6 += 0. By hand, pool after 3E =
 *       65 533 012 400, payout(4E) = 999 954 (§3 derivation):
 *       power 1.3e7 / 1e7 / 1e7 (Σ 3.3e7)
 *       share0 = floor(999954 × 13/33) = floor(12 999 402 / 33) = 393 921
 *       share1 = share2 = floor(9 999 540 / 33) = 303 016
 *       base0  = floor(393921 × 10/13) = floor(3 939 210 / 13) = 303 016
 *       gross 90 905, commission 9 090, net 81 815 → key 5 (the only
 *       delegator left) += 81 815, key 0 += 312 106;
 *       Σ 312 106 + 81 815 + 2 × 303 016 = 999 953.
 * The withdrawn coin itself is locked until L(h) + 12E = 15E, pinned in
 * test_v2_native.c §13b — so it earns only while it cannot be spent.
 * RED ON THE PRE-REV2 TREE: the rev-1 min(copy, live) paid key 6 0 at E
 * (live 0) and spread its slice over the others. RED ON THE PRE-P3 TREE:
 * 3E read the live-built snapshot(2E) and copy(E) — key 6 += 0 at 3E.
 * KILLED BY: reading the live delegations at H; paying a withdrawn stake
 * past L(h) (at 4E); dropping it before L(h) (at 2E or 3E). */
#define WD_V0_4    312106ULL
#define WD_V12_4   303016ULL
#define WD_D5_4    81815ULL
#define WD_SUM4    999953ULL
static int t_withdrawn_mid_epoch(void) {
    fixture_t fx;
    CHECK(fx_stage1(&fx, "withdrawn", SPECD, 3, DELS, 2) == 0, "stage1");
    CHECK(fx_stage2(&fx) == 0, "stage2");
    {
        split_t s4;
        split_specd(SC_PAYOUT4, D5_AMT, 0, &s4);
        CHECK(s4.v0 == WD_V0_4 && s4.v12 == WD_V12_4 && s4.d5 == WD_D5_4 &&
              s4.d6 == 0 && s4.sum == WD_SUM4,
              "FIXTURE GUARD: the 4E constants match the formula");
    }
    CHECK(fx_drive(&fx, E - 1, ALL3) == 0, "drive to E-1");
    CHECK(copy_of(fx.w, 0, 0, 6) == D6_AMT, "key 6 is in copy(0)");
    CHECK(undelegate_by_hand(&fx, 6, 0, D6_AMT, 0xB6) == 0,
          "key 6 fully withdraws mid-epoch");
    CHECK(supply_closes(fx.w), "the equation closes after the exit");
    OK();

    CHECK(fx_drive(&fx, E, ALL3) == 0, "boundary E");
    CHECK(accrual_of(fx.w, 6) == EXP_D6 && accrual_of(fx.w, 5) == EXP_D5 &&
          accrual_of(fx.w, 0) == EXP_V0 && accrual_of(fx.w, 1) == EXP_V12,
          "E: the withdrawn delegator is paid for the epoch it was counted "
          "in (the §2 numbers)");
    CHECK(q1(fx.w, "SELECT reward_pool FROM supply_tracking") == SC_POOL1,
          "E: the pool debited by Σ credited");
    OK();

    CHECK(fx_drive(&fx, 2 * E, ALL3) == 0, "boundary 2E");
    CHECK(accrual_of(fx.w, 6) == EXP_D6 + SC_Q1_2 &&
          accrual_of(fx.w, 5) == EXP_D5 + SC_Q3_2 &&
          accrual_of(fx.w, 0) == EXP_V0 + SC_V0_2,
          "2E: still in the governing snapshot(E) and copy(0) — still "
          "paid (it has not left the voting power yet)");
    CHECK(q1(fx.w, "SELECT reward_pool FROM supply_tracking") == SC_POOL2,
          "2E: the pool debited by Σ credited");
    OK();

    CHECK(fx_drive(&fx, 3 * E, ALL3) == 0, "boundary 3E");
    CHECK(accrual_of(fx.w, 6) == EXP_D6 + SC_Q1_2 + SC_Q1_3 &&
          accrual_of(fx.w, 5) == EXP_D5 + SC_Q3_2 + SC_Q3_3 &&
          accrual_of(fx.w, 0) == EXP_V0 + SC_V0_2 + SC_V0_3,
          "3E: snapshot(2E) was built from copy(0) under okuma B — the "
          "withdrawn stake still governs (2E, 3E] and is still paid");
    CHECK(q1(fx.w, "SELECT reward_pool FROM supply_tracking") == SC_POOL3,
          "3E: the pool debited by Σ credited");
    OK();

    CHECK(fx_drive(&fx, 4 * E, ALL3) == 0, "boundary 4E");
    CHECK(accrual_of(fx.w, 6) == EXP_D6 + SC_Q1_2 + SC_Q1_3,
          "4E: out of the voting power since L = 3E — no longer paid");
    CHECK(accrual_of(fx.w, 5) == EXP_D5 + SC_Q3_2 + SC_Q3_3 + WD_D5_4 &&
          accrual_of(fx.w, 0) == EXP_V0 + SC_V0_2 + SC_V0_3 + WD_V0_4 &&
          accrual_of(fx.w, 1) == EXP_V12 + SC_V12_2 + SC_V12_3 + WD_V12_4,
          "4E: the governing snapshot(3E) without it, by hand");
    CHECK(q1(fx.w, "SELECT reward_pool FROM supply_tracking") ==
              SC_POOL3 - WD_SUM4,
          "4E: the pool debited by Σ credited");
    CHECK(supply_closes(fx.w), "the equation closes after 4E");
    OK();
    fx_close(&fx);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §3c PARTIAL WITHDRAWAL + TOP-UP, the reward side (design §7.1
 * "Testler": "kısmi çekiş + top-up … kazanç ≤ kilitli sermayeninki") —
 * engine
 * ════════════════════════════════════════════════════════════════════ */

/* Key 5 holds 3e14 with key 0. In the LAST block of epoch (0, E] it
 * (1) partially withdraws PW_W = 1e14 — the delegation falls to 2e14,
 * both key-0 totals fall by 1e14, and the release comes back to key 5
 * as a UTXO born locked to L(E) + 12E, and (2) tops up with FRESH coin
 * PW_T = 2e14 — the delegation rises to 4e14, both totals by 2e14, and
 * the coin enters from outside (genesis/current supply += 2e14, exactly
 * seed-then-spend of a new coin). By hand: the changes stand for
 * transactions in block E, which run before boundary E (h = E is itself
 * a boundary): nb(E) = E, L(E) = 3E (tokenomics-v3 P3-2, "okuma B"),
 * release unlock = 3E + 12E = 15E.
 *
 * WHY THE CHANGES SIT RIGHT BEFORE A BOUNDARY BLOCK, honestly labelled:
 * the fixture lane cannot sign envelopes, so the moves are written by
 * hand between blocks, and the next block must declare SYSTEM and CORE
 * touched or the untouched-domain guard rejects the out-of-band drift
 * (nodus_witness_v2_apply.c phase 8). A boundary block that pays does
 * declare both (phase 6e); an empty mid-epoch block declares neither.
 *
 * Expected, by hand (every figure re-derived in-test by split_specd):
 *   E  (governing snapshot(0), source copy(0): key 5 = 3e14, key 6 =
 *      1e14) → the §2 numbers: key 5 += 79 412.
 *   2E (governing snapshot(E) — built at GENESIS, before both moves —
 *      source copy(0)) → the §3 2E numbers: key 5 += 79 411 on 3e14.
 *      The withdrawn 1e14 is still paid; the 2e14 top-up is NOT paid yet.
 *   3E (tokenomics-v3 P3-2: governing snapshot(2E), built at boundary E
 *      by "okuma B" from copy(0) — BEFORE both moves; source copy(0))
 *      → the §3 3E numbers at 3:1: key 5 += 79 410 on 3e14. The
 *      withdrawn 1e14 is still paid (it leaves the voting power at L =
 *      3E); the top-up is still not.
 *   4E (governing snapshot(3E), built at boundary 2E from copy(E) — AFTER
 *      both moves: key 0 total 1e15 + 4e14 + 1e14 = 1.5e15; source
 *      copy(E): key 5 = 4e14, key 6 = 1e14), payout 999 954 (§3):
 *      power 1.5e7 / 1e7 / 1e7 (Σ 3.5e7)
 *      share0 = floor(999954 × 15/35) = floor(2 999 862 / 7) = 428 551
 *      share1 = share2 = floor(1 999 908 / 7) = 285 701
 *      base0  = floor(428551 × 2/3) = floor(857 102 / 3) = 285 700
 *      gross 142 851, commission 14 285, net 128 566
 *      → key 5 += floor(128566 × 4/5) = floor(514 264 / 5) = 102 852,
 *        key 6 += floor(128 566 / 5) = 25 713, key 0 += 299 985;
 *        Σ 299 985 + 102 852 + 25 713 + 2 × 285 701 = 999 952.
 *      The top-up is paid from 4E — the first epoch whose governing
 *      snapshot was built from a copy taken after it — and the withdrawn
 *      1e14 no longer.
 *
 * LOCKED CAPITAL per epoch, the minimum over the epoch of key 5's
 * bonded amount + its still-locked release (the release is locked until
 * 15E, beyond every boundary here):
 *   (0, E]:   3e14 all epoch (the moves land in its last block and only
 *             re-label 1e14 from bonded to locked)       → earned on 3e14
 *   (E, 2E]:  4e14 bonded + 1e14 locked = 5e14           → earned on 3e14
 *   (2E, 3E]: 4e14 bonded + 1e14 locked = 5e14           → earned on 3e14
 *   (3E, 4E]: 4e14 bonded + 1e14 locked = 5e14           → earned on 4e14
 * At no boundary does key 5 earn on more than it had locked; checked
 * below as increment <= split_specd(payout, locked, 1e14).d5.
 *
 * RED ON THE PRE-REV2 TREE: the rev-1 split read copy(H−E) and
 * min(copy, live): at 2E key 5 counted min(copy(E) 4e14, live 4e14) =
 * 4e14 — the top-up paid an epoch early; and the release was unlock 0.
 * RED ON THE PRE-P3 TREE: snapshot(2E) was built from the LIVE rows at E
 * (after the moves), so 3E paid key 5 on 4e14 (102 854) and the release
 * unlock was 14E.
 * KILLED BY: a distribution that reads the LIVE delegations (2E would
 * pay 4e14); a selector that ranks the live stake (3E pays 4e14); one
 * that reads a copy other than src(H) (the consistency gate faults); one
 * that keeps paying the withdrawn part after L(h) (4E would pay 5e14). */
#define PW_W       100000000000000ULL   /* the partial withdrawal, 1M */
#define PW_T       200000000000000ULL   /* the fresh top-up, 2M       */
#define PW_V0_4    299985ULL
#define PW_V12_4   285701ULL
#define PW_D5_4    102852ULL
#define PW_D6_4    25713ULL
#define PW_SUM4    999952ULL

/* Rewrite one delegation amount and move both of its validator's
 * delegated totals by `delta` (signed), by hand. @return 0 / -1. */
static int deleg_move_by_hand(fixture_t *fx, int dkey, int vkey,
                              uint64_t new_amount, int64_t delta) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(fx->w->db,
            "UPDATE delegations SET amount = ?1 WHERE delegator_pubkey = ?2 "
            "AND validator_pubkey = ?3", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)new_amount);
    sqlite3_bind_blob(st, 2, g_pk[dkey], DNAC_PUBKEY_SIZE, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 3, g_pk[vkey], DNAC_PUBKEY_SIZE, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE || sqlite3_changes(fx->w->db) != 1) return -1;
    st = NULL;
    if (sqlite3_prepare_v2(fx->w->db,
            "UPDATE validators SET total_delegated = total_delegated + ?1, "
            "external_delegated = external_delegated + ?1 "
            "WHERE pubkey = ?2", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)delta);
    sqlite3_bind_blob(st, 2, g_pk[vkey], DNAC_PUBKEY_SIZE, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return (rc == SQLITE_DONE && sqlite3_changes(fx->w->db) == 1) ? 0 : -1;
}

static int t_partial_withdraw_topup(void) {
    fixture_t fx;
    CHECK(fx_stage1(&fx, "pwtopup", SPECD, 3, DELS, 2) == 0, "stage1");
    CHECK(fx_stage2(&fx) == 0, "stage2");
    const uint64_t rel_unlock =
        (3 + (uint64_t)DNAC_UNDELEGATE_LOCK_EPOCHS) * E;   /* L(E) + 12E */
    {
        split_t s4;
        split_specd(SC_PAYOUT4, D5_AMT - PW_W + PW_T, D6_AMT, &s4);
        CHECK(D5_AMT - PW_W + PW_T == 400000000000000ULL &&
              s4.v0 == PW_V0_4 && s4.v12 == PW_V12_4 &&
              s4.d5 == PW_D5_4 && s4.d6 == PW_D6_4 && s4.sum == PW_SUM4,
              "FIXTURE GUARD: the 4E constants match the formula");
        uint64_t L = 0;
        CHECK(nodus_v2_power_exit_boundary(E, &L) == 0 && L == 3 * E &&
              rel_unlock > 4 * E,
              "FIXTURE GUARD: L(E) = 3E (P3-2), and the release stays "
              "locked past every boundary this case drives");
    }
    OK();

    CHECK(fx_drive(&fx, E - 1, ALL3) == 0, "drive to E-1");
    /* (1) the partial withdrawal: 3e14 → 2e14, release 1e14 locked */
    CHECK(deleg_move_by_hand(&fx, 5, 0, D5_AMT - PW_W,
                             -(int64_t)PW_W) == 0, "partial withdrawal");
    CHECK(seed_utxo(&fx, 5, PW_W, 0xB5) == 0, "the release");
    {
        char sql[320];
        snprintf(sql, sizeof(sql),
                 "UPDATE utxo_set SET unlock_block = %llu WHERE owner = "
                 "'%s' AND amount = %llu",
                 (unsigned long long)rel_unlock, g_fp[5],
                 (unsigned long long)PW_W);
        CHECK(run_sql(fx.w->db, sql) == 0 &&
              sqlite3_changes(fx.w->db) == 1, "born locked");
    }
    /* (2) the top-up with fresh coin: 2e14 → 4e14 */
    CHECK(deleg_move_by_hand(&fx, 5, 0, D5_AMT - PW_W + PW_T,
                             (int64_t)PW_T) == 0, "top-up");
    {
        char sql[224];
        snprintf(sql, sizeof(sql),
                 "UPDATE supply_tracking SET genesis_supply = genesis_supply "
                 "+ %llu, current_supply = current_supply + %llu "
                 "WHERE id = 1", (unsigned long long)PW_T,
                 (unsigned long long)PW_T);
        CHECK(run_sql(fx.w->db, sql) == 0, "the fresh coin enters");
    }
    CHECK(supply_closes(fx.w), "the equation closes after both moves");
    OK();

    /* E */
    CHECK(fx_drive(&fx, E, ALL3) == 0, "boundary E");
    const uint64_t k5_e = accrual_of(fx.w, 5);
    CHECK(k5_e == EXP_D5 && accrual_of(fx.w, 6) == EXP_D6 &&
          accrual_of(fx.w, 0) == EXP_V0 &&
          q1(fx.w, "SELECT reward_pool FROM supply_tracking") == SC_POOL1,
          "E: paid on the 3e14 of copy(0) — the §2 numbers");
    {
        split_t cap;
        split_specd(PAYOUT, D5_AMT, D6_AMT, &cap);        /* locked 3e14 */
        CHECK(k5_e <= cap.d5, "E: earned <= on the capital locked (3e14)");
    }
    CHECK(copy_of(fx.w, E, 0, 5) == D5_AMT - PW_W + PW_T,
          "copy(E) carries the post-move 4e14");
    OK();

    /* 2E */
    CHECK(fx_drive(&fx, 2 * E, ALL3) == 0, "boundary 2E");
    const uint64_t k5_2e = accrual_of(fx.w, 5) - k5_e;
    CHECK(k5_2e == SC_Q3_2,
          "2E: paid on 3e14 — the withdrawn 1e14 still counts (it leaves "
          "the power at L = 3E), the 2e14 top-up does not yet");
    CHECK(accrual_of(fx.w, 0) == EXP_V0 + SC_V0_2 &&
          q1(fx.w, "SELECT reward_pool FROM supply_tracking") == SC_POOL2,
          "2E: the members by snapshot(E)'s power, pool debited by Σ");
    {
        split_t cap;
        split_specd(SC_PAYOUT2, D5_AMT - PW_W + PW_T + PW_W, D6_AMT, &cap);
        CHECK(k5_2e <= cap.d5,
              "2E: earned <= on the capital locked (4e14 + 1e14)");
    }
    OK();

    /* 3E — P3-2: snapshot(2E) was built from copy(0), src(3E) = copy(0) */
    CHECK(fx_drive(&fx, 3 * E, ALL3) == 0, "boundary 3E");
    const uint64_t k5_3e = accrual_of(fx.w, 5) - k5_e - k5_2e;
    CHECK(k5_3e == SC_Q3_3,
          "3E: paid on 3e14 — the withdrawn 1e14 still counts (it leaves "
          "the power at L = 3E), the 2e14 top-up does not yet");
    CHECK(accrual_of(fx.w, 6) == EXP_D6 + SC_Q1_2 + SC_Q1_3 &&
          accrual_of(fx.w, 0) == EXP_V0 + SC_V0_2 + SC_V0_3 &&
          q1(fx.w, "SELECT reward_pool FROM supply_tracking") == SC_POOL3,
          "3E: the §3 3E numbers on the governing snapshot(2E)");
    {
        split_t cap;
        split_specd(SC_PAYOUT3, D5_AMT - PW_W + PW_T + PW_W, D6_AMT, &cap);
        CHECK(k5_3e <= cap.d5,
              "3E: earned <= on the capital locked (4e14 + 1e14)");
    }
    OK();

    /* 4E */
    CHECK(fx_drive(&fx, 4 * E, ALL3) == 0, "boundary 4E");
    const uint64_t k5_4e = accrual_of(fx.w, 5) - k5_e - k5_2e - k5_3e;
    CHECK(k5_4e == PW_D5_4,
          "4E: paid on 4e14 — the top-up from the first epoch whose "
          "governing snapshot was built from a copy taken after it, the "
          "withdrawn 1e14 no longer");
    CHECK(accrual_of(fx.w, 6) == EXP_D6 + SC_Q1_2 + SC_Q1_3 + PW_D6_4 &&
          accrual_of(fx.w, 0) == EXP_V0 + SC_V0_2 + SC_V0_3 + PW_V0_4 &&
          accrual_of(fx.w, 1) == EXP_V12 + SC_V12_2 + SC_V12_3 + PW_V12_4 &&
          q1(fx.w, "SELECT reward_pool FROM supply_tracking") ==
              SC_POOL3 - PW_SUM4,
          "4E: the hand-derived split on the governing snapshot(3E)");
    {
        split_t cap;
        split_specd(SC_PAYOUT4, D5_AMT - PW_W + PW_T + PW_W, D6_AMT, &cap);
        CHECK(k5_4e <= cap.d5,
              "4E: earned <= on the capital locked (4e14 + 1e14)");
    }
    CHECK(supply_closes(fx.w), "the equation closes after 4E");
    OK();
    fx_close(&fx);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §3e the econ band's decimal_unit refusal
 * ════════════════════════════════════════════════════════════════════ */

/* Stage 1 commits the three band rows with THIS build's values, exactly
 * as the version-3 genesis commits them (param 200/201/202,
 * effective_block 0 — nodus_chain_config.h NODUS_CC_ECON_*; the fixture's
 * v2x_seed_prepare). Then decimal_unit alone is changed to a value this
 * build did not compile.
 * RED ON THE PRE-FIX TREE: the loader refused only epoch_length and
 * returned 0 with present == 1 and decimal_unit == 10 × the compiled one.
 * KILLED BY: deleting the decimal_unit refusal; returning -1 without
 * zeroing the struct. */
static int t_econ_params_decimal_unit(void) {
    fixture_t fx;
    /* tokenomics-v3 P4: the band is committed by stage 1 itself
     * (v2x_seed_prepare writes the three rows at
     * NODUS_CC_ECON_EFFECTIVE_BLOCK with this build's values, as the
     * genesis derivation does) — the explicit INSERT this case used to
     * make would now collide with it */
    CHECK(fx_stage1(&fx, "dunit", SPECD, 3, DELS, 2) == 0, "stage1");
    nodus_v2_econ_params_t p;
    CHECK(nodus_witness_v2_econ_params_load(fx.w, &p) == 0 &&
          p.present == 1 &&
          p.decimal_unit == (uint64_t)DNAC_DECIMAL_UNIT &&
          p.epoch_length == (uint64_t)DNAC_EPOCH_LENGTH &&
          p.blocks_per_year == (uint64_t)DNAC_BLOCKS_PER_YEAR,
          "CONTROL: a band matching this build loads");
    OK();

    const char *fmt = "UPDATE chain_config_history SET new_value = %llu "
                      "WHERE param_id = %u AND effective_block = %llu";
    char sql[256];
    snprintf(sql, sizeof(sql), fmt,
             (unsigned long long)DNAC_DECIMAL_UNIT * 10ULL,
             (unsigned)NODUS_CC_ECON_DECIMAL_UNIT,
             (unsigned long long)NODUS_CC_ECON_EFFECTIVE_BLOCK);
    CHECK(run_sql(fx.w->db, sql) == 0, "poke decimal_unit");
    memset(&p, 0xA5, sizeof(p));
    CHECK(nodus_witness_v2_econ_params_load(fx.w, &p) == -1,
          "a committed decimal_unit this build did not compile is "
          "REFUSED");
    CHECK(p.present == 0 && p.decimal_unit == 0 && p.epoch_length == 0 &&
          p.blocks_per_year == 0,
          "and the struct holds nothing usable on the refusal");
    OK();

    snprintf(sql, sizeof(sql), fmt, (unsigned long long)DNAC_DECIMAL_UNIT,
             (unsigned)NODUS_CC_ECON_DECIMAL_UNIT,
             (unsigned long long)NODUS_CC_ECON_EFFECTIVE_BLOCK);
    CHECK(run_sql(fx.w->db, sql) == 0, "restore decimal_unit");
    CHECK(nodus_witness_v2_econ_params_load(fx.w, &p) == 0 &&
          p.present == 1,
          "restored, the band loads again — the refusal was the value's");
    OK();
    fx_close(&fx);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §3f A COMMISSION INCREASE WAITS TWO EPOCHS (P3 fix round; decision file
 * §3 2026-09-24 "komisyon artışı 2 epoch sonra") — engine
 * ════════════════════════════════════════════════════════════════════ */

/* The split of split_specd with key 0's commission as a parameter. */
static void split_specd_c(uint64_t payout, uint64_t a5, uint64_t a6,
                          uint64_t comm_bps, split_t *o) {
    const uint64_t t0 = BOND_BASE + a5 + a6;
    const uint64_t p0 = t0 / (uint64_t)DNAC_DECIMAL_UNIT;
    const uint64_t p1 = BOND_BASE / (uint64_t)DNAC_DECIMAL_UNIT;
    const uint64_t sp = p0 + 2 * p1;
    const uint64_t s0 = mdiv(payout, p0, sp);
    const uint64_t s1 = mdiv(payout, p1, sp);
    const uint64_t base = mdiv(s0, BOND_BASE, t0);
    const uint64_t gross = s0 - base;
    const uint64_t com = mdiv(gross, comm_bps, 10000);
    const uint64_t net = gross - com;
    o->v0  = base + com;
    o->v12 = s1;
    o->d5  = (a5 + a6) ? mdiv(net, a5, a5 + a6) : 0;
    o->d6  = (a5 + a6) ? mdiv(net, a6, a5 + a6) : 0;
    o->sum = o->v0 + 2 * o->v12 + o->d5 + o->d6;
}

/* A pending increase written by hand: exactly the two columns
 * rtn_vupd_exec's increase arm writes (pending rate + effective height);
 * the current rate does not move. */
static int pending_by_hand(fixture_t *fx, int key, uint16_t bps,
                           uint64_t peff) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(fx->w->db,
            "UPDATE validators SET pending_commission_bps = ?1, "
            "pending_effective_block = ?2 WHERE pubkey = ?3",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(st, 1, (int)bps);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)peff);
    sqlite3_bind_blob(st, 3, g_pk[key], DNAC_PUBKEY_SIZE, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return (rc == SQLITE_DONE && sqlite3_changes(fx->w->db) == 1) ? 0 : -1;
}

/* The LIVE commission of `key`. */
static uint64_t live_comm(fixture_t *fx, int key) {
    dnac_validator_record_t v;
    if (nodus_validator_get(fx->w, g_pk[key], &v) != 0) return UINT64_MAX;
    return v.commission_bps;
}

/* The commission the snapshot of `epoch` froze for `key`; UINT64_MAX when
 * the snapshot or the entry is absent. */
static uint64_t snap_comm(fixture_t *fx, uint64_t epoch, int key) {
    dna_vset_snapshot_t *s = NULL;
    if (nodus_witness_vset_get(fx->w, epoch, &s, NULL) != 0 || !s)
        return UINT64_MAX;
    uint64_t c = UINT64_MAX;
    for (uint16_t i = 0; i < s->active_count; i++)
        if (memcmp(s->entries[i].pubkey, g_pk[key], DNAC_PUBKEY_SIZE) == 0)
            c = s->entries[i].commission_bps;
    dna_vset_free(&s);
    return c;
}

/* THE WORKED EXAMPLE, under P3-1 "okuma B" (B = E):
 *   Key 0 (10%, delegators key 5 = 3e14 and key 6 = 1e14) raises its
 *   commission to 20% IN boundary block B — the by-hand write sits right
 *   before block E, which is the state an envelope in block E leaves,
 *   since envelopes apply before the boundary (nodus_witness_v2_apply.c
 *   phase 6e). Key 5 reacts by leaving: a full UNDELEGATE right before
 *   block 2E. For every copy this is the same as leaving at B+1: copy(E)
 *   (written at boundary E) holds it, copy(2E) does not.
 *   A rate a boundary X activates (step 1) is frozen by step 5's
 *   commit_next(X) into snapshot(X+E), governs (X+E, X+2E] and is PAID
 *   at X+2E by copy(X−E)'s weights (src = H−3E):
 *     writer H+2E (TODAY): peff = 3E → activates at 3E → snapshot(4E)
 *       carries 20% → first paid at 5E from copy(2E) — key 5 is NOT in
 *       it. At 4E, snapshot(3E) (built at 2E) still carries 10% and pays
 *       key 5 from copy(E) at the OLD rate.
 *     writer H+E (the P3 tree): peff = 2E → activates at 2E → snapshot(3E)
 *       carries 20% → paid at 4E from copy(E) — which still holds key 5:
 *       key 5 pays the rate it left over. That is the finding the
 *       decision cites; the second run below reproduces it.
 *   A MID-EPOCH increase: key 1 (0%) gets pending 5% with peff = 3E + 1,
 *   the value the writer stores for H = E + 1 (written by hand at E−1 —
 *   the activator reads only the stored height, and a by-hand write can
 *   only land before a boundary block). It must NOT activate at 3E and
 *   must activate at 4E (the first boundary >= 3E + 1).
 *   A DECREASE is immediate — pinned at block level in test_v2_native.c
 *   §13 (VALIDATOR_UPDATE P1), not repeated here.
 * RED ON THE P3 TREE: the writer stored H+E (test_v2_native.c H4); run 1
 * with that peff is run 2, where key 5 IS charged 20% at 4E.
 * KILLED BY: an activator that fires before its stored height; a
 * snapshot that takes the commission from anywhere but the live row at
 * its build; a distribution reading a copy other than src(H). */
static int notice_run(const char *tag, uint64_t peff0, uint64_t want_c3,
                      int full) {
    fixture_t fx;
    CHECK(fx_stage1(&fx, tag, SPECD, 3, DELS, 2) == 0, "stage1");
    CHECK(fx_stage2(&fx) == 0, "stage2");
    CHECK(fx_drive(&fx, E - 1, ALL3) == 0, "drive to E-1");
    CHECK(pending_by_hand(&fx, 0, 2000, peff0) == 0,
          "key 0's increase in boundary block E");
    CHECK(pending_by_hand(&fx, 1, 500, 3 * E + 1) == 0,
          "key 1's mid-epoch increase (stored height 3E+1)");
    CHECK(fx_drive(&fx, 2 * E - 1, ALL3) == 0, "drive to 2E-1");
    CHECK(live_comm(&fx, 0) == 1000, "no activation at E");
    CHECK(copy_of(fx.w, E, 0, 5) == D5_AMT, "key 5 is in copy(E)");
    CHECK(undelegate_by_hand(&fx, 5, 0, D5_AMT, 0xC5) == 0,
          "key 5 leaves in reaction");
    OK();
    CHECK(fx_drive(&fx, 3 * E, ALL3) == 0, "drive to 3E");
    CHECK(copy_of(fx.w, 2 * E, 0, 5) == UINT64_MAX,
          "key 5 is not in copy(2E)");
    CHECK(snap_comm(&fx, 3 * E, 0) == want_c3,
          "snapshot(3E), built at 2E, carries the rate active at 2E");
    CHECK(live_comm(&fx, 0) == 2000, "the increase is live by 3E");
    CHECK(live_comm(&fx, 1) == 0 && snap_comm(&fx, 4 * E, 1) == 0,
          "the mid-epoch increase (peff 3E+1) has NOT activated at 3E");
    OK();

    /* boundary 4E: governing snapshot(3E), source copy(E) — key 5 in */
    const uint64_t pool4 = q1(fx.w, "SELECT reward_pool FROM supply_tracking");
    const uint64_t pay4 = pool4 >> NODUS_V2_GEN_REWARD_DIVISOR_LOG2;
    const uint64_t d5a = accrual_of(fx.w, 5), d6a = accrual_of(fx.w, 6);
    split_t s4, s4_other;
    split_specd_c(pay4, D5_AMT, D6_AMT, want_c3, &s4);
    split_specd_c(pay4, D5_AMT, D6_AMT, want_c3 == 1000 ? 2000 : 1000,
                  &s4_other);
    CHECK(s4.d5 != s4_other.d5,
          "FIXTURE GUARD: 10% and 20% give key 5 different amounts");
    CHECK(fx_drive(&fx, 4 * E, ALL3) == 0, "boundary 4E");
    CHECK(accrual_of(fx.w, 5) - d5a == s4.d5 &&
          accrual_of(fx.w, 6) - d6a == s4.d6,
          "4E pays key 5 and key 6 at snapshot(3E)'s rate on copy(E)");
    CHECK(live_comm(&fx, 1) == 500,
          "the mid-epoch increase activates at 4E, the first boundary >= "
          "3E+1");
    CHECK(supply_closes(fx.w), "the equation closes at 4E");
    OK();
    if (!full) { fx_close(&fx); return 0; }

    /* boundary 5E: governing snapshot(4E), built at 3E from copy(2E) —
     * the 20% rate, and key 5 absent */
    CHECK(snap_comm(&fx, 4 * E, 0) == 2000,
          "snapshot(4E), built at 3E, carries the new rate");
    CHECK(snap_comm(&fx, 5 * E, 1) == 500,
          "snapshot(5E), built at 4E, carries key 1's new rate");
    const uint64_t pool5 = q1(fx.w, "SELECT reward_pool FROM supply_tracking");
    const uint64_t pay5 = pool5 >> NODUS_V2_GEN_REWARD_DIVISOR_LOG2;
    const uint64_t d5b = accrual_of(fx.w, 5), d6b = accrual_of(fx.w, 6);
    split_t s5;
    split_specd_c(pay5, 0, D6_AMT, 2000, &s5);
    CHECK(fx_drive(&fx, 5 * E, ALL3) == 0, "boundary 5E");
    CHECK(accrual_of(fx.w, 5) == d5b,
          "5E: the new rate is first paid from copy(2E) — key 5, who left "
          "in reaction, is never charged it");
    CHECK(accrual_of(fx.w, 6) - d6b == s5.d6,
          "5E: key 6, who stayed, pays the new rate");
    CHECK(supply_closes(fx.w), "the equation closes at 5E");
    OK();
    fx_close(&fx);
    return 0;
}

static int t_commission_notice(void) {
    /* run 1 — TODAY's writer: peff = H + 2E = 3E for H = E */
    if (notice_run("notice2", 3 * E, 1000, 1) != 0) return 1;
    /* run 2 — the P3 tree's writer, peff = H + E = 2E: the defect the
     * decision cites, reproduced (key 5 charged 20% at 4E) */
    if (notice_run("notice1", 2 * E, 2000, 0) != 0) return 1;
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §4 BAR MISS forfeits the WHOLE share (decision §3 (2)), engine-driven
 * ════════════════════════════════════════════════════════════════════ */

/* Key 0 (with its two delegators) never signs; keys 1 and 2 sign every
 * block. At E key 0 fails the shared predicate (nodus_witness_v2_
 * attendance_meets_bar), so key 0, key 5 and key 6 accrue NOTHING and the
 * whole 411764 share stays in the pool; keys 1 and 2 are paid in full.
 * RED ON THE PRE-P2 TREE: the missed seat was BURNED (total_burned > 0)
 * and the pool never existed.
 * KILLED BY: paying the delegators of a bar-missing validator; burning
 * the forfeited share. */
static int t_bar_miss(void) {
    fixture_t fx;
    CHECK(fx_stage1(&fx, "barmiss", SPECD, 3, DELS, 2) == 0, "stage1");
    CHECK(fx_stage2(&fx) == 0, "stage2");
    CHECK(fx_drive(&fx, E, (1u << 1) | (1u << 2)) == 0, "drive to E");
    CHECK(accrual_of(fx.w, 0) == 0 && accrual_of(fx.w, 5) == 0 &&
          accrual_of(fx.w, 6) == 0,
          "the bar-missing validator AND its delegators earn nothing");
    CHECK(accrual_of(fx.w, 1) == EXP_V12 && accrual_of(fx.w, 2) == EXP_V12,
          "the attending members are paid their own shares");
    CHECK(q1(fx.w, "SELECT reward_pool FROM supply_tracking")
              == POOL - 2 * EXP_V12,
          "the forfeited share stays in the pool");
    CHECK(q1(fx.w, "SELECT total_burned FROM supply_tracking") == 0,
          "and NOTHING is burned");
    CHECK(supply_closes(fx.w), "the equation closes");
    OK();
    fx_close(&fx);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §5 PAYDAY (P2-7)
 * ════════════════════════════════════════════════════════════════════ */

/* Locate a payday UTXO by the identity RECOMPUTED from the two exported
 * derivations, never by reading the row's own key back. */
static int payday_row(nodus_witness_t *w, uint64_t h, uint32_t idx,
                      uint64_t *amount, char owner[129],
                      uint64_t *unlock, uint64_t *bh) {
    uint8_t txh[64], nul[64];
    if (nodus_witness_v2_settlement_tx_hash(h, txh) != 0) return -1;
    if (nodus_witness_v2_settlement_nullifier(
            txh, NODUS_V2_SETTLE_KIND_ACCRUAL,
            NODUS_V2_SETTLE_OUT_IDX_BASE + idx, nul) != 0)
        return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT amount, owner, unlock_block, block_height, tx_hash "
            "FROM utxo_set WHERE nullifier = ?1", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, nul, 64, SQLITE_TRANSIENT);
    int rc = -1;
    if (sqlite3_step(st) == SQLITE_ROW &&
        sqlite3_column_bytes(st, 1) == 128 &&
        sqlite3_column_bytes(st, 4) == 64 &&
        memcmp(sqlite3_column_blob(st, 4), txh, 64) == 0) {
        *amount = (uint64_t)sqlite3_column_int64(st, 0);
        memcpy(owner, sqlite3_column_text(st, 1), 128);
        owner[128] = '\0';
        *unlock = (uint64_t)sqlite3_column_int64(st, 2);
        *bh     = (uint64_t)sqlite3_column_int64(st, 3);
        rc = 0;
    }
    sqlite3_finalize(st);
    return rc;
}

/* The five recipients of SPECD in owner_fp ASC order — the payday's
 * output-index order. */
static void owners_sorted(int out[5]) {
    int k[5] = { 0, 1, 2, 5, 6 };
    for (int a = 1; a < 5; a++)
        for (int b = a; b > 0 &&
             memcmp(g_fpraw[k[b - 1]], g_fpraw[k[b]], 64) > 0; b--) {
            int t = k[b]; k[b] = k[b - 1]; k[b - 1] = t;
        }
    memcpy(out, k, sizeof(k));
}

static int payday_direct(fixture_t *fx, uint64_t h, uint64_t interval,
                         uint32_t *n) {
    if (run_sql(fx->w->db, "BEGIN IMMEDIATE") != 0) return -1;
    int rc = nodus_witness_v2_payday_apply(fx->w, h, interval, NULL, NULL,
                                           n);
    if (run_sql(fx->w->db, rc == 0 ? "COMMIT" : "ROLLBACK") != 0) return -1;
    return rc;
}

/* RED ON THE PRE-P2 TREE: the function, the kind 0x22 and the accrual
 * table do not exist; the old settlement paid at EVERY boundary.
 * KILLED BY: paying on a non-multiple; paying from the delegation row
 * (the exited delegator would be skipped); leaving the rows behind;
 * a nonzero unlock. */
static int t_payday(void) {
    fixture_t fx;
    CHECK(fx_stage1(&fx, "payday", SPECD, 3, DELS, 2) == 0, "stage1");
    CHECK(fx_stage2(&fx) == 0, "stage2");
    CHECK(fx_drive(&fx, E, ALL3) == 0, "drive to E (the §2 accruals)");
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_reward_accrual") == 5,
          "five accrual rows to pay");
    OK();

    /* NOT a payday: (E / E) % 2 = 1 */
    uint32_t n = 99;
    CHECK(payday_direct(&fx, E, 2, &n) == 0 && n == 0,
          "a non-multiple of the interval pays nothing");
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_reward_accrual") == 5 &&
          q1(fx.w, "SELECT COUNT(*) FROM utxo_set") == 1,
          "and moves nothing");
    OK();

    /* key 6 FULLY EXITS before the payday: its delegation row is gone
     * and the principal is released to it as a UTXO (the UNDELEGATE
     * movement, by hand — the equation must still close). */
    {
        CHECK(nodus_delegation_delete(fx.w, g_pk[6], g_pk[0]) == 0,
              "key 6 exits");
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(fx.w->db,
                  "UPDATE validators SET total_delegated = "
                  "total_delegated - ?1, external_delegated = "
                  "external_delegated - ?1 WHERE pubkey = ?2",
                  -1, &st, NULL) == SQLITE_OK, "prep");
        sqlite3_bind_int64(st, 1, (sqlite3_int64)D6_AMT);
        sqlite3_bind_blob(st, 2, g_pk[0], DNAC_PUBKEY_SIZE, SQLITE_TRANSIENT);
        CHECK(sqlite3_step(st) == SQLITE_DONE, "step");
        sqlite3_finalize(st);
        CHECK(seed_utxo(&fx, 6, D6_AMT, 0xB6) == 0, "principal release");
        CHECK(supply_closes(fx.w), "the equation closes after the exit");
    }
    OK();

    /* THE payday: interval 1 */
    n = 0;
    CHECK(payday_direct(&fx, E, 1, &n) == 0 && n == 5,
          "a multiple of the interval pays every accrual row");
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_reward_accrual") == 0,
          "the accrual table is EMPTY after the payday");
    {
        int ord[5];
        const uint64_t want[N_KEYS] = {
            [0] = EXP_V0, [1] = EXP_V12, [2] = EXP_V12,
            [5] = EXP_D5, [6] = EXP_D6
        };
        owners_sorted(ord);
        for (uint32_t i = 0; i < 5; i++) {
            uint64_t amt = 0, unl = 1, bh = 0;
            char owner[129];
            CHECK(payday_row(fx.w, E, i, &amt, owner, &unl, &bh) == 0,
                  "a payday UTXO sits at its recomputed identity "
                  "(tx_hash(E), kind 0x22, index 400 + rank)");
            CHECK(amt == want[ord[i]] &&
                  strcmp(owner, g_fp[ord[i]]) == 0,
                  "paid to the RIGHT owner (owner_fp ASC rank) the "
                  "accrued amount");
            CHECK(unl == 0 && bh == E, "unlock 0, block_height = H");
        }
    }
    CHECK(accrual_of(fx.w, 6) == 0, "key 6's row is gone too — PAID");
    OK();
    CHECK(supply_closes(fx.w),
          "accrual → utxo: the equation closes after the payday");
    OK();

    /* a second call at the same height has nothing left to pay */
    n = 99;
    CHECK(payday_direct(&fx, E, 1, &n) == 0 && n == 0,
          "an empty accrual table pays nothing");
    OK();

    /* 0 is not an interval */
    CHECK(payday_direct(&fx, E, 0, &n) == -2, "interval 0 is a FAULT");
    OK();
    fx_close(&fx);
    return 0;
}

/* The interval reader's three answers (nodus_witness_v2_payout_
 * interval): a database with no document, not flagged a successor → the
 * default; the same database flagged as a version-3 successor → FAULT (a
 * version-3 chain always stores its document); the sealed chain → its
 * stored document's interval. A non-default interval through a block is
 * the harness's (test_v2_rewards.sh, STAGEF_PAYOUT_INTERVAL_EPOCHS=2)
 * and test_v2_gen's stored-document cases. */
static int t_payout_interval(void) {
    fixture_t fx;
    /* tokenomics-v3 P4: the "no document" answers are read on the
     * stage-1 database — BEFORE the seal stores the document — with the
     * successor flag set each way; the third answer is the stored
     * document's own interval after the seal. */
    CHECK(fx_stage1(&fx, "interval", SPECD, 3, DELS, 2) == 0, "stage1");
    CHECK(nodus_witness_v2_gen_stored_doc_present(fx.w) == 0,
          "FIXTURE GUARD: no document before the seal");
    uint64_t iv = 0;
    fx.w->v2_successor = 0;
    CHECK(nodus_witness_v2_payout_interval(fx.w, &iv) == 0 &&
          iv == (uint64_t)NODUS_V2_GEN_PAYOUT_INTERVAL_EPOCHS_DEFAULT &&
          iv == 24,
          "no document, not a successor: the decision's 24");
    fx.w->v2_successor = 1;
    iv = 777;
    CHECK(nodus_witness_v2_payout_interval(fx.w, &iv) == -2 && iv == 777,
          "a version-3 successor with no document is a FAULT, not 24");
    OK();
    CHECK(fx_stage2(&fx) == 0, "stage2");
    CHECK(nodus_witness_v2_gen_stored_doc_present(fx.w) == 1,
          "the seal stored the document");
    iv = 0;
    CHECK(nodus_witness_v2_payout_interval(fx.w, &iv) == 0 && iv == 24,
          "a version-3 chain reads its document's interval (the "
          "fixture document carries the default, 24)");
    OK();
    fx_close(&fx);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §6 FAULT STAGES
 * ════════════════════════════════════════════════════════════════════ */

/* F55 (every accrual row credited, pool not debited), F56 (pool
 * debited) and F59 (copy(H) written + pruned), each injected at the
 * paying boundary E: the whole-database digest must not move, and a
 * clean retry must then commit the real distribution. */
static int t_fault_distribution(void) {
    static const nodus_v2_apply_fail_t pts[3] = {
        V2AP_FAIL_AFTER_DIST_ACCRUED, V2AP_FAIL_AFTER_DIST_APPLIED,
        V2AP_FAIL_AFTER_BALANCE_COPY
    };
    static const char *tags[3] = { "f55", "f56", "f59" };
    for (int leg = 0; leg < 3; leg++) {
        fixture_t fx;
        CHECK(fx_stage1(&fx, tags[leg], SPECD, 3, DELS, 2) == 0, "stage1");
        CHECK(fx_stage2(&fx) == 0, "stage2");
        CHECK(fx_drive(&fx, E - 1, ALL3) == 0, "drive to E-1");
        int rc = 0;
        CHECK(fx_block_inject(&fx, ALL3, pts[leg], &rc) == 0,
              "the injected boundary rolled back byte-identically");
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM v2_reward_accrual") == 0 &&
              q1(fx.w, "SELECT reward_pool FROM supply_tracking") == POOL,
              "no accrual row and no pool movement survived");
        CHECK(q1f(fx.w, "SELECT COUNT(*) FROM v2_balance_copy "
                        "WHERE epoch_start = %llu", E) == 0,
              "no copy(E) row survived");
        OK();
        CHECK(fx_block_mask(&fx, ALL3, V2AP_FAIL_NONE, NULL) == 0,
              "clean retry at the boundary");
        CHECK(accrual_of(fx.w, 0) == EXP_V0 &&
              q1(fx.w, "SELECT reward_pool FROM supply_tracking")
                  == POOL - EXP_SUM,
              "the retry distributed for real");
        CHECK(supply_closes(fx.w), "the equation closes after the retry");
        OK();
        fx_close(&fx);
    }
    return 0;
}

/* The payday's two stages through its own callback (its engine ids F57/
 * F58 are unreachable on the fixture lane — §5's note). */
static nodus_v2_epoch_stage_t g_stop_at;
static int stage_cb(void *ud, nodus_v2_epoch_stage_t s, uint32_t idx) {
    (void)ud; (void)idx;
    return s == g_stop_at;
}

static int t_fault_payday(void) {
    static const nodus_v2_epoch_stage_t st[2] = {
        NODUS_V2_EPST_PAYDAY_EMITTED, NODUS_V2_EPST_PAYDAY_APPLIED
    };
    fixture_t fx;
    CHECK(fx_stage1(&fx, "f5758", SPECD, 3, DELS, 2) == 0, "stage1");
    CHECK(fx_stage2(&fx) == 0, "stage2");
    CHECK(fx_drive(&fx, E, ALL3) == 0, "drive to E");
    for (int leg = 0; leg < 2; leg++) {
        uint8_t d0[64], d1[64];
        CHECK(v2x_db_digest(fx.w, d0) == 0, "digest pre");
        g_stop_at = st[leg];
        uint32_t n = 0;
        CHECK(run_sql(fx.w->db, "BEGIN IMMEDIATE") == 0, "begin");
        CHECK(nodus_witness_v2_payday_apply(fx.w, E, 1, stage_cb, NULL,
                                            &n) == -2 && n == 0,
              "the injected stage fails the payday");
        CHECK(run_sql(fx.w->db, "ROLLBACK") == 0, "rollback");
        CHECK(v2x_db_digest(fx.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
              "the rollback is byte-identical");
        OK();
    }
    uint32_t n = 0;
    CHECK(payday_direct(&fx, E, 1, &n) == 0 && n == 5,
          "a clean payday afterwards pays all five");
    OK();
    fx_close(&fx);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §7 DETERMINISM TWIN
 * ════════════════════════════════════════════════════════════════════ */

/* KILLED BY: any unordered iteration reaching an accrual amount or a
 * payday identity. The twins inserted their validators AND delegations
 * in OPPOSITE order, so a distribution keyed on insertion order — rather
 * than on the snapshot's committed order and owner_fp ASC — would credit
 * or pay differently and the CORE roots would differ. */
static int t_determinism_twin(void) {
    fixture_t a, b;
    CHECK(fx_stage1(&a, "twin_a", SPECD, 3, DELS, 2) == 0, "a stage1");
    CHECK(fx_stage2(&a) == 0, "a stage2");
    CHECK(fx_stage1(&b, "twin_b", SPECD_REV, 3, DELS_REV, 2) == 0,
          "b stage1");
    CHECK(fx_stage2(&b) == 0, "b stage2");
    CHECK(fx_drive(&a, E, ALL3) == 0, "a drive");
    CHECK(fx_drive(&b, E, ALL3) == 0, "b drive");

    uint8_t sa[64], ca[64], sb[64], cb[64];
    CHECK(nodus_witness_system_root_v2(a.w, sa) == 0 &&
          nodus_witness_core_root_v2(a.w, ca) == 0, "a roots");
    CHECK(nodus_witness_system_root_v2(b.w, sb) == 0 &&
          nodus_witness_core_root_v2(b.w, cb) == 0, "b roots");
    CHECK(q1(a.w, "SELECT COUNT(*) FROM v2_reward_accrual") == 5,
          "not vacuous: the compared state holds a paying boundary");
    CHECK(memcmp(ca, cb, 64) == 0 && memcmp(sa, sb, 64) == 0,
          "the twins agree on CORE and SYSTEM after the paying boundary");
    OK();

    uint32_t na = 0, nb = 0;
    CHECK(payday_direct(&a, E, 1, &na) == 0 &&
          payday_direct(&b, E, 1, &nb) == 0 && na == 5 && nb == 5,
          "both twins pay");
    CHECK(nodus_witness_core_root_v2(a.w, ca) == 0 &&
          nodus_witness_core_root_v2(b.w, cb) == 0 &&
          memcmp(ca, cb, 64) == 0,
          "and agree on CORE after the payday");
    OK();
    fx_close(&a);
    fx_close(&b);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════ */

int main(void) {
    keys_init();

    struct { const char *name; int (*fn)(void); } tests[] = {
        { "§1 the frozen balance copy", t_balance_copy },
        { "§2 distribution math through the engine", t_distribution_math },
        { "§3 the split reads the source copy src(H)", t_source_copy },
        { "§3a the consistency gate faults a divergent copy",
          t_consistency_gate },
        { "§3b a mid-epoch withdrawal is paid until it leaves the power",
          t_withdrawn_mid_epoch },
        { "§3c partial withdrawal + top-up: earned <= locked capital",
          t_partial_withdraw_topup },
        { "§3e decimal_unit build-identity refusal",
          t_econ_params_decimal_unit },
        { "§3f a commission increase waits two epochs (okuma B)",
          t_commission_notice },
        { "§4 a bar miss forfeits the whole share", t_bar_miss },
        { "§5 payday", t_payday },
        { "§5 the payout interval reader", t_payout_interval },
        { "§6 F55/F56/F59 roll back whole", t_fault_distribution },
        { "§6 the payday stages roll back whole", t_fault_payday },
        { "§7 determinism twin", t_determinism_twin },
    };

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        printf("== %s\n", tests[i].name);
        if (tests[i].fn() != 0) {
            fprintf(stderr, "FAILED: %s\n", tests[i].name);
            return 1;
        }
    }
    printf("test_v2_econ: OK (%d checks)\n", g_checks);
    return 0;
}
