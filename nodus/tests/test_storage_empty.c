/**
 * @file nodus/tests/test_storage_empty.c
 * @brief Storage reward v1 rev 4 (the ARCHIVE reward) — the behaviours no
 *        other test drives: a GEN_STORAGE chain with ZERO registered
 *        storage members, the first registration after empty boundaries,
 *        a payday crossed with zero and with one storage member, and the
 *        0x73 fetch's refusal code 6 (FAULT).
 *
 * Decisions: docs/plans/decisions/2026-10-05-storage-reward-is-for-
 * archive.md (K1 amount = block count, K5 / K5a fail_streak, K6a / K6b the
 * 0x73 wire and its codes — 6 FAULT, "one request in flight per peer",
 * K9 grace = n × E, K9a n counts only segments published at or before
 * H − E, n = 0 at the first storage boundary, K10 generation 4 on the EVM
 * generation), 2026-10-05-archive-reward-bytes-approved.md, 2026-10-08-
 * kurultay-14-hf6-summary.md K10 (storage is voted on the live chain
 * BEFORE HF-6; these cases are among the tests that gate that vote).
 * Design docs/plans/2026-10-05-archive-reward-design.md rev 4; bytes
 * docs/plans/2026-10-04-storage-reward-bytes.md §2 (S(H)).
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 * Twin fixtures in every engine case (same seed, same genesis, every
 * block applied to both; after EVERY block the committed global roots
 * are equal; at every boundary and every block that carries an envelope
 * each committed SYSTEM head also equals its runtime's recomputation).
 * Seven seeded validators with REAL keys (every block carries their
 * COMMIT votes), treasury pool 1 = 10^16, param 9 at 2, param 14
 * (EVM_ACTIVE) at 3, param 16 (the storage vote) at 4. KM is the one
 * storage-only (non-validator) key.
 *
 *  empty_chain_then_first_member  (no pre-seeded segment)
 *   - EVERY boundary B = E .. 25E with nobody registered (the zero-member
 *     check, on BOTH twins): the block applies (no FAULT — a -2 at a
 *     boundary would fail v2x_cmt_apply); storage_set(B) EXISTS (rc 0,
 *     not "absent") with count 0 and member_count 0; S(B) equals both
 *     dna_v2_storage_set_hash(B, NULL, 0) and the test's own restatement
 *     of bytes §2 (SHA3-512("NDS.STSET.v1" zero-padded to 16 ‖ B u64 BE ‖
 *     0 u32 BE)); no v2_storage_set_members row; the header rows kept are
 *     exactly min(B/E, 3) (the prune keeps set(B−2E) .. set(B)); no
 *     v2_storage_nodes row; pool 1 untouched (= 10^16 — no storage
 *     debit); KM has no accrual; the CORE invariant holds. The settlement
 *     step runs over an empty set(H) from B = 3E on.
 *   - 2E + 1: all seven seats report for H = E against the EMPTY set
 *     (bitmap_len 0): every report applies and is stored as an empty
 *     BLOB; boundary 3E settles H = E with F1 met (7/7 power reported)
 *     over zero members: no FAULT, pool 1 untouched, the reports pruned.
 *   - PAYDAY with zero members at iv·E (iv = the chain's own
 *     payout_interval_epochs, 24 by the v3 default — checked <= 25): the
 *     validators' distribution has accrual rows before it (checked > 0,
 *     so the payday has something to pay), the boundary applies,
 *     v2_reward_accrual is empty after it, the CORE invariant holds on
 *     both twins, pool 1 untouched.
 *   - FIRST REGISTRATION after 25 empty boundaries: KM registers at
 *     25E + 5; set(25E) stays empty; at 26E segment k = 1 is PUBLISHED BY
 *     THE CHAIN (P + 2E = 26E, from the real v2_blocks rows) and KM
 *     enters set(26E) — the same boundary. K9a: the segment published
 *     at that boundary is not counted (n = 0) — the frozen grace_until
 *     and the registry grace_until are 0; KM's eligible list at 26E is
 *     exactly {1} (probed at once).
 *   - 27E + 1: all seven seats report for H = 26E with KM's bit 1;
 *     boundary 28E settles H = 26E: weight P (K1), KM credited
 *     floor(budget · P / P) = pool1 >> 16, pool 1 debited exactly that,
 *     fail_streak 0, the CORE invariant holds on both twins.
 *
 *  first_member_then_payday  (eight segments PRE-SEEDED, published at 1)
 *   - boundaries E, 2E, 3E empty (the zero-member check above).
 *   - KM registers at 3E + 5 and enters set(4E). set(3E) EXISTS (empty),
 *     so this is not "the first storage boundary": K9a counts every
 *     pre-existing segment KM now holds and did not hold at 3E — the
 *     test's own count over holders(k, set(4E)) — and the frozen and
 *     registry grace_until equal 4E + n·E (n = 8: a sole member holds
 *     every segment). Each boundary 4E .. 12E: KM's frozen and registry
 *     grace_until stay 4E + n·E (n = 0 afterwards: held at B − E); KM
 *     has no eligible segment while H < grace_until and all eight at
 *     H = grace_until.
 *   - reports for H = 12E at 13E + 1; boundary 14E: KM credited
 *     pool1 >> 16 (sole weight), pool 1 debited exactly that,
 *     fail_streak 0.
 *   - PAYDAY with one member at iv·E (checked >= 15E): KM's accrual
 *     (exactly its storage credit) becomes spendable UTXO value owned by
 *     KM's hex fingerprint (Σ before 0, after = the accrual), the accrual
 *     table is empty, pool 1 untouched at the payday, the CORE invariant
 *     holds on both twins.
 *   - then, on fixture A at tip iv·E (KM an ACTIVE member of S(H)),
 *     THE 0x73 SERVING SIDE's code 6: nodus_witness_stfetch_serve answers
 *     NOT_HELD (store and directory absent: admission passed) and then,
 *     one corruption at a time, each undone and the NOT_HELD baseline
 *     re-proven: a stored S(H) that does not re-derive from its members,
 *     a member_count that disagrees with the member rows, an unreadable
 *     registry table, an unreadable segment list, an unreadable
 *     v2_blocks (tip) → REF_FAULT (6), never NOT_MEMBER / UNKNOWN_SET /
 *     NOT_PUBLISHED; nodus_stfetch_answer_build refuses an invalid
 *     request with REF_FAULT; the code-6 refusal is exactly kind ‖ rq ‖
 *     6 (66 bytes), decodes, and is never an OK shape; an ANSWER with no
 *     outstanding request is dropped by nodus_witness_sthold_on_msg
 *     (0) and an undecodable 0x73 message is refused (-1).
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: a default EVM-enabled (standalone, non-Windows) build —
 * GEN_STORAGE exists only there (K10). DNAC_EPOCH_LENGTH >= 8 (checked);
 * every height is derived from it, so the production 720 and the harness
 * 15 both work. The chain's payout interval must be <= 25 epochs (case 1)
 * and >= 15 (case 2) — checked, a FAIL otherwise, never a skip.
 * Environment: none. Cost: case 1 applies 28E blocks to each of two
 * fixtures, case 2 iv·E (24E) — at the production E = 720 that is 20,160
 * + 17,280 = 37,440 blocks per fixture, ≈ 75,000 block applications:
 * minutes, not seconds.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * Two /tmp/test_storage_empty_* directories per case, removed at the end
 * (left behind when a CHECK aborts).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - "No FAULT" is observed as v2x_cmt_apply returning 0 for the
 *    boundary block; the storage step's own result struct (settled,
 *    accrued, set_count) is not visible through the engine. That 3E
 *    takes the F1-met branch over the empty set is by construction (all
 *    seven seats reported), not observed.
 *  - The SYSTEM-head recomputation runs at boundaries and at blocks with
 *    an envelope, not at every idle block (the global-root twin compare
 *    does run at every block).
 *  - The GEN_STORAGE pins and the storage vote literal are the
 *    independent-oracle literals the runtime selfcheck re-derives at the
 *    seeded genesis; if they stop re-deriving, both cases FAIL at genesis.
 *  - Case 2's eight segments are PRE-SEEDED rows (published_height 1, a
 *    state the chain never writes — the same device as test_storage_b2).
 *    Case 1's k = 1 is the only segment the chain publishes itself, from
 *    the fixture's real v2_blocks rows. So: "a segment published AT the
 *    entry boundary counts 0" is proven on the engine by case 1; "a
 *    pre-existing segment taken over after empty boundaries counts 1" by
 *    case 2.
 *  - The genesis carries a non-zero validator reward pool (10^16, the
 *    test_v2_econ device — a row derive_v3 never writes) so that the
 *    validator distribution accrues and the zero-member payday has rows
 *    to pay; without it that payday would be a no-op crossing.
 *  - The validator committee is seeded, not a ceremony's (v2_genesis_
 *    fixture.h "HOW IT CAN LIE"); the payday's validator payouts are
 *    checked only through the CORE invariant and the empty accrual
 *    table, KM's through its own UTXO sum.
 *  - Code 6 is driven through the pure serving function over a corrupted
 *    database; the 4004 transport, the refusal actually leaving on the
 *    wire and the client's peer rotation are not driven. "One request in
 *    flight per peer" is the client's rt->out gate in
 *    nodus_witness_storage_holder.c (fetch_send / the JOB_FETCH branch of
 *    nodus_witness_sthold_tick), reachable only with a live p2p host — it
 *    is NOT tested here; only its receiving half (an answer nobody asked
 *    for is dropped) is.
 *  - "Twin" is two fixtures in one process, not a 7-machine run.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_econ.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "witness/nodus_witness_v2_gen.h"
#include "witness/nodus_witness_v2_storage.h"
#include "witness/nodus_witness_storage_fetch.h"
#include "witness/nodus_witness_storage_holder.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_validator.h"
#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_v2_spend.h"

#include "dnac/dnac.h"
#include "dnac/cmt_pb.h"
#include "dnac/domain_wire.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/effect_wire.h"
#include "dnac/ledger_ids.h"
#include "dnac/ledger_roots_v2.h"
#include "dnac/validator.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#include "v2_genesis_fixture.h"

#include <errno.h>
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

#define E_LEN    ((uint64_t)DNAC_EPOCH_LENGTH)
#define P_LEN    ((uint64_t)DNA_V2_SEGMENT_BLOCKS)
#define D2       ((uint64_t)DNAC_CFG_RULESET_GEN2_D2)
#define DS       ((uint64_t)DNAC_CFG_RULESET_GEN_STORAGE_D)
#define FEE      ((uint64_t)DNAC_MIN_FEE_RAW)
#define BOND     ((uint64_t)DNAC_STORAGE_STAKE_MIN)
#define POOL1    10000000000000000ULL          /* 10^16 raw (pool 1)     */
#define RPOOL    10000000000000000ULL          /* 10^16 raw validator
                                                * reward pool (genesis) */
#define PK_LEN   ((size_t)QGP_DSA87_PUBLICKEYBYTES)
#define AUTH_LEN (1u + NODUS_RT_AUTH_SIGNER_LEN)
#define MAX_SEGS 8u

/* restated from nodus_witness_rt_native.c (static there) */
#define STREG_LEN      (2592u + 8u + 64u)
#define REP_FIXED      78u

#define H9   2u
#define HE   3u       /* EVM_ACTIVE (param 14): GEN_STORAGE is built on the
                       * EVM generation (K10) */
#define H14  4u       /* RULESET_GEN_STORAGE (param 16): the storage edge */

static void put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

/* ══ keys ══════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t fp[64];
    char    hex[129];
} sk_key_t;

/* V0..V6 the validators; KM the one storage-only node. */
enum { V0, V1, V2, V3, V4, V5, V6, KM, N_KEYS };
#define N_VAL 7
static sk_key_t g_k[N_KEYS];

static void hex_of(const uint8_t raw[64], char out[129]) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[2 * i]     = hx[raw[i] >> 4];
        out[2 * i + 1] = hx[raw[i] & 15];
    }
    out[128] = '\0';
}

static int keys_make(void) {
    for (int i = 0; i < N_KEYS; i++) {
        uint8_t seed[32];
        memset(seed, 0x41 + i, sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_k[i].pk, g_k[i].sk, seed) != 0)
            return -1;
        if (qgp_sha3_512(g_k[i].pk, PK_LEN, g_k[i].fp) != 0) return -1;
        hex_of(g_k[i].fp, g_k[i].hex);
    }
    return 0;
}

/* ══ fixture ═══════════════════════════════════════════════════════════ */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain16[16];
    uint8_t          chain32[DNA_CHAIN_ID_LEN];
} fixture_t;

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    nodus_witness_sthold_free(fx->w);
    if (fx->w->db) sqlite3_close(fx->w->db);
    free(fx->w);
    fx->w = NULL;
    char cmd[200];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", fx->dir);
    if (system(cmd) != 0) { /* best effort */ }
}

static int fx_dir(fixture_t *fx, const char *tag) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_storage_empty_%s_XXXXXX",
             tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain16, 0x5C, sizeof(fx->chain16));
    return 0;
}

static int q_u64(nodus_witness_t *w, const char *sql, uint64_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int rc = sqlite3_step(st);
    sqlite3_int64 v = rc == SQLITE_ROW ? sqlite3_column_int64(st, 0) : -1;
    sqlite3_finalize(st);
    if (rc != SQLITE_ROW || v < 0) return -1;
    *out = (uint64_t)v;
    return 0;
}

/* the one coin: KM's bond + fee */
static const uint8_t COIN_SEED = 0xA1;
static const uint64_t COIN_AMOUNT = BOND + FEE;
static uint8_t g_nul[64];

static int coin_nul(uint8_t out[64]) {
    uint8_t pre[160];
    memcpy(pre, g_k[KM].hex, 128);
    memset(pre + 128, COIN_SEED, 32);
    return qgp_sha3_512(pre, sizeof(pre), out);
}

static int seed_coin(nodus_witness_t *w) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
            "tx_hash, output_index, block_height, created_at, "
            "unlock_block, domain_id) VALUES "
            "(?1, ?2, ?3, zeroblob(64), zeroblob(64), 0, 0, 0, 0, 1)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, g_nul, 64, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, g_k[KM].hex, 128, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)COIN_AMOUNT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

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

/* the pre-seeded segment root of k (case 2 only — HOW IT CAN LIE) */
static int seg_root(uint64_t k, uint8_t out[64]) {
    uint8_t pre[22 + 8];
    memcpy(pre, "test_storage_empty/seg", 22);
    put64(pre + 22, k);
    return qgp_sha3_512(pre, sizeof(pre), out);
}

/* A seeded GEN_STORAGE chain: seven real-key validators, pool 1 = 10^16,
 * KM's coin, `n_segs` pre-seeded segments (published_height 1). */
static int fx_open(fixture_t *fx, const char *tag, uint64_t n_segs) {
    if (n_segs > MAX_SEGS) return -1;
    if (fx_dir(fx, tag) != 0) return -1;
    nodus_witness_t *w = fx->w;
    if (v2x_seed_prepare(w, fx->chain16, 0) != 0) return -1;
    if (cc_row(w, DNAC_CFG_HF2_ACTIVE, DNAC_CFG_HF2_ACTIVE_ON, 1, 11) != 0 ||
        cc_row(w, DNAC_CFG_RULESET_GEN2, D2, H9, 12) != 0 ||
        cc_row(w, DNAC_CFG_EVM_ACTIVE, (uint64_t)DNAC_CFG_EVM_ACTIVE_D, HE,
               14) != 0 ||
        cc_row(w, DNAC_CFG_RULESET_GEN_STORAGE, DS, H14, 13) != 0)
        return -1;
    uint64_t bonds = 0;
    for (int i = 0; i < N_VAL; i++) {
        dnac_validator_record_t v;
        memset(&v, 0, sizeof(v));
        memcpy(v.pubkey, g_k[i].pk, DNAC_PUBKEY_SIZE);
        v.self_stake = DNAC_SELF_STAKE_AMOUNT;
        v.status = (uint8_t)DNAC_VALIDATOR_ACTIVE;
        v.active_since_block = 1;
        memcpy(v.unstake_destination_fp, g_k[i].hex, 129);
        if (nodus_validator_insert(w, &v) != 0) return -1;
        bonds += DNAC_SELF_STAKE_AMOUNT;
    }
    {
        char sql[128];
        snprintf(sql, sizeof(sql), "UPDATE validator_stats SET value = %d "
                 "WHERE key = 'active_count'", N_VAL);
        if (v2x_sql(w->db, sql) != 0) return -1;
    }
    for (uint32_t p = 1; p <= 9; p++) {
        char sql[128];
        snprintf(sql, sizeof(sql), "INSERT INTO v2_treasury (pool_id, "
                 "balance) VALUES (%u, %llu)", (unsigned)p,
                 (unsigned long long)(p == 1 ? POOL1 : 0ULL));
        if (v2x_sql(w->db, sql) != 0) return -1;
    }
    if (seed_coin(w) != 0) return -1;
    {
        /* not a real genesis: a non-zero validator reward pool (the
         * test_v2_econ device, v2_genesis_fixture.h "HOW IT CAN LIE") so
         * the validator distribution accrues every epoch and a payday
         * has rows to pay */
        const uint64_t supply = COIN_AMOUNT + bonds + POOL1 + RPOOL;
        char sql[400];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO supply_tracking (id, genesis_supply, "
                 "total_burned, total_minted, current_supply, "
                 "last_tx_hash, last_sequence, reward_pool) VALUES (1, "
                 "%llu, 0, 0, %llu, zeroblob(64), 0, %llu)",
                 (unsigned long long)supply, (unsigned long long)supply,
                 (unsigned long long)RPOOL);
        if (v2x_sql(w->db, sql) != 0) return -1;
    }
    for (uint64_t k = 1; k <= n_segs; k++) {
        uint8_t r[64];
        sqlite3_stmt *st = NULL;
        if (seg_root(k, r) != 0 ||
            sqlite3_prepare_v2(w->db, "INSERT INTO v2_storage_segments (k, "
                               "root, published_height) VALUES (?1, ?2, 1)",
                               -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)k);
        sqlite3_bind_blob(st, 2, r, 64, SQLITE_TRANSIENT);
        int rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) return -1;
    }
    v2x_seed_not_real(V2X_SEED_NOT_REAL_UTXOS);
    if (v2x_seed_genesis(w, fx->chain16, 0, NULL, 0, fx->chain32) != 0)
        return -1;
    return 0;
}

/* every block from height 2 carries all seven COMMIT votes */
static uint8_t g_vaddr[N_VAL][32];
static int32_t g_vflag[N_VAL];

static void mk_block(nodus_v2_block_t *b, uint64_t h,
                     const nodus_v2_envelope_t *envs, size_t n) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = nodus_v2_epoch_for_height(h);
    b->envs = envs;
    b->n_envs = n;
    if (h > 1) {
        b->cmt.votes_address = (const uint8_t (*)[32])g_vaddr;
        b->cmt.votes_block_id_flag = g_vflag;
        b->cmt.votes_len = N_VAL;
    }
}

static int sys_head_recomputes(nodus_witness_t *w) {
    sqlite3_stmt *st = NULL;
    uint8_t committed[64], now[64];
    int ok = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT head FROM v2_domain_heads WHERE "
                           "domain_id = 0", -1, &st, NULL) != SQLITE_OK)
        return -1;
    if (sqlite3_step(st) == SQLITE_ROW &&
        sqlite3_column_bytes(st, 0) == DNA_V2_DOMHEAD_ENC_LEN) {
        memcpy(committed, (const uint8_t *)sqlite3_column_blob(st, 0) + 4,
               64);
        ok = 0;
    }
    sqlite3_finalize(st);
    const nodus_domain_runtime_t *rt = NULL;
    if (ok != 0 ||
        nodus_witness_v2_runtime_for(w, DNA_DOMAIN_SYSTEM, 1, &rt) != 0 ||
        !rt || !rt->state_root || rt->state_root(rt, w, now) != 0)
        return -1;
    return memcmp(committed, now, 64) == 0 ? 0 : -1;
}

/* The per-boundary hook (run on BOTH twins right after a boundary block
 * applied); NULL = none. */
static int (*g_hook)(nodus_witness_t *w, uint64_t B);

static int apply_both(fixture_t *a, fixture_t *b, uint64_t h,
                      const nodus_v2_envelope_t *envs, size_t n,
                      uint32_t *codes) {
    nodus_v2_tx_result_t ra[8], rb[8];
    nodus_v2_block_t ba, bb;
    if (n > 8) return -1;
    memset(ra, 0, sizeof(ra));
    memset(rb, 0, sizeof(rb));
    mk_block(&ba, h, envs, n);
    mk_block(&bb, h, envs, n);
    ba.cmt.results = ra;
    ba.cmt.results_cap = 8;
    bb.cmt.results = rb;
    bb.cmt.results_cap = 8;
    if (v2x_cmt_apply(a->w, &ba) != 0 || v2x_cmt_apply(b->w, &bb) != 0) {
        fprintf(stderr, "block %llu: %s | %s\n", (unsigned long long)h,
                ba.out_reason, bb.out_reason);
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        if (ra[i].code != rb[i].code) return -1;
        if (codes) codes[i] = ra[i].code;
    }
    uint8_t ca[64], cb[64];
    if (nodus_witness_v2_committed_global_root(a->w, ca) != 0 ||
        nodus_witness_v2_committed_global_root(b->w, cb) != 0 ||
        memcmp(ca, cb, 64) != 0) {
        fprintf(stderr, "block %llu: twin global roots differ\n",
                (unsigned long long)h);
        return -1;
    }
    const int boundary = (h % E_LEN) == 0;
    if ((boundary || n > 0) &&
        (sys_head_recomputes(a->w) != 0 || sys_head_recomputes(b->w) != 0)) {
        fprintf(stderr, "block %llu: SYSTEM head does not recompute\n",
                (unsigned long long)h);
        return -1;
    }
    if (boundary && g_hook &&
        (g_hook(a->w, h) != 0 || g_hook(b->w, h) != 0))
        return -1;
    return 0;
}

static int run_idle(fixture_t *a, fixture_t *b, uint64_t *h,
                    uint64_t target) {
    while (*h < target) {
        if (apply_both(a, b, *h + 1, NULL, 0, NULL) != 0) return -1;
        (*h)++;
    }
    return 0;
}

static int submit(fixture_t *A, fixture_t *B, uint64_t h, uint8_t **envs,
                  size_t *lens, size_t n, uint32_t *codes) {
    nodus_v2_envelope_t v[8];
    if (n > 8) return -1;
    for (size_t i = 0; i < n; i++) {
        v[i].env_bytes = envs[i];
        v[i].env_len = lens[i];
    }
    int rc = apply_both(A, B, h, v, n, codes);
    for (size_t i = 0; i < n; i++) { free(envs[i]); envs[i] = NULL; }
    return rc;
}

/* ══ envelopes (the shapes test_storage_b2 builds) ═════════════════════ */

/* SYSFUND call: in_count ‖ nullifier ‖ out_count 0 */
static uint32_t fund_call(uint8_t *dst, const uint8_t nul[64]) {
    dst[0] = 1;
    memcpy(dst + 1, nul, 64);
    dst[65] = 0;
    return 66;
}

/* KM's 2-leg STORAGE_REGISTER envelope, really signed on both legs. */
static int reg_env(nodus_witness_t *w, uint64_t height, uint8_t **out,
                   size_t *out_len) {
    static uint8_t call[STREG_LEN];
    static uint8_t fund[66];
    static uint8_t auth[2][AUTH_LEN];
    dna_domain_manifest_t sys, core;
    *out = NULL;
    memcpy(call, g_k[KM].pk, PK_LEN);
    put64(call + PK_LEN, BOND);
    memcpy(call + PK_LEN + 8, g_k[KM].fp, 64);       /* payee = node_fp */
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_SYSTEM, NULL, &sys, NULL)
        != 0 ||
        nodus_witness_domreg_get(w, DNA_DOMAIN_CORE, NULL, &core, NULL) != 0)
        return -1;
    uint32_t fl = fund_call(fund, g_nul);
    dna_env_leg_in_t legs[2];
    memset(legs, 0, sizeof(legs));
    legs[0].hdr.domain_id = DNA_DOMAIN_SYSTEM;
    legs[0].hdr.runtime_op = DNA_SYSRULE_STORAGE_REGISTER;
    legs[0].hdr.ruleset_version = sys.ruleset_version;
    legs[0].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[0].hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[0].hdr.call_len = STREG_LEN;
    legs[0].hdr.auth_len = AUTH_LEN;
    legs[0].hdr.res_max_effects = 8;
    legs[0].hdr.res_max_effect_bytes = 16384;
    legs[0].call_data = call;
    legs[0].auth_data = auth[0];
    legs[1].hdr.domain_id = DNA_DOMAIN_CORE;
    legs[1].hdr.runtime_op = DNA_CORERULE_SYSFUND;
    legs[1].hdr.ruleset_version = core.ruleset_version;
    legs[1].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    legs[1].hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    legs[1].hdr.call_len = fl;
    legs[1].hdr.auth_len = AUTH_LEN;
    legs[1].hdr.res_max_effects = 40;
    legs[1].hdr.res_max_effect_bytes = 16384;
    legs[1].call_data = fund;
    legs[1].auth_data = auth[1];
    memset(auth, 0, sizeof(auth));

    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.fee_amount = FEE;
    in.res_max_total_units = 400000;
    in.leg_count = 2;
    in.legs = legs;

    dna_env_leg_ctx_t lctx[2];
    memset(lctx, 0, sizeof(lctx));
    lctx[0].domain_id = DNA_DOMAIN_SYSTEM;
    lctx[0].ruleset_version = sys.ruleset_version;
    memcpy(lctx[0].ruleset_hash, sys.ruleset_hash, 64);
    lctx[1].domain_id = DNA_DOMAIN_CORE;
    lctx[1].ruleset_version = core.ruleset_version;
    memcpy(lctx[1].ruleset_hash, core.ruleset_hash, 64);

    size_t len = 0, used = 0;
    if (dna_env_encoded_size(legs, 2, &len) != 0) return -1;
    uint8_t *bytes = malloc(len);
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    int ok = -1;
    do {
        if (!bytes || !pf) break;
        if (dna_env_encode(&in, bytes, len, &used) != 0 || used != len) break;
        if (dna_env_preflight(bytes, len, w->v2_chain32, height, lctx, 2, pf)
            != DNA_ENV_PF_OK)
            break;
        int bad = 0;
        for (int L = 0; L < 2 && !bad; L++) {
            size_t sl = 0;
            auth[L][0] = 1;
            memcpy(auth[L] + 1, g_k[KM].pk, PK_LEN);
            if (qgp_dsa87_sign(auth[L] + 1 + PK_LEN, &sl,
                               pf->auth_digest[L], 64, g_k[KM].sk) != 0)
                bad = 1;
        }
        if (bad) break;
        if (dna_env_encode(&in, bytes, len, &used) != 0 || used != len) break;
        ok = 0;
    } while (0);
    free(pf);
    if (ok != 0) { free(bytes); return -1; }
    *out = bytes;
    *out_len = len;
    return 0;
}

/* The STORAGE_REPORT call body (bytes §3). */
static uint32_t rep_call(uint8_t *dst, uint64_t h, uint32_t seat,
                         const uint8_t s[64], const uint8_t *bm,
                         uint16_t bl) {
    put64(dst, h);
    put32(dst + 8, seat);
    memcpy(dst + 12, s, 64);
    dst[76] = (uint8_t)(bl >> 8);
    dst[77] = (uint8_t)bl;
    if (bl) memcpy(dst + REP_FIXED, bm, bl);
    return REP_FIXED + bl;
}

/* A 1-leg STORAGE_REPORT envelope, fee 0, signed by validator `signer`. */
static int rep_env(nodus_witness_t *w, uint64_t height, const uint8_t *call,
                   uint32_t call_len, int signer, uint8_t **out,
                   size_t *out_len) {
    static uint8_t auth[AUTH_LEN];
    dna_domain_manifest_t sys;
    *out = NULL;
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_SYSTEM, NULL, &sys, NULL)
        != 0)
        return -1;
    dna_env_leg_in_t leg;
    memset(&leg, 0, sizeof(leg));
    leg.hdr.domain_id = DNA_DOMAIN_SYSTEM;
    leg.hdr.runtime_op = DNA_SYSRULE_STORAGE_REPORT;
    leg.hdr.ruleset_version = sys.ruleset_version;
    leg.hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
    leg.hdr.auth_kind = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    leg.hdr.call_len = call_len;
    leg.hdr.auth_len = AUTH_LEN;
    leg.hdr.res_max_effects = 8;
    leg.hdr.res_max_effect_bytes = 16384;
    leg.call_data = call;
    leg.auth_data = auth;
    memset(auth, 0, sizeof(auth));
    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.fee_amount = 0;
    in.res_max_total_units = 400000;
    in.leg_count = 1;
    in.legs = &leg;
    dna_env_leg_ctx_t lctx;
    memset(&lctx, 0, sizeof(lctx));
    lctx.domain_id = DNA_DOMAIN_SYSTEM;
    lctx.ruleset_version = sys.ruleset_version;
    memcpy(lctx.ruleset_hash, sys.ruleset_hash, 64);
    size_t len = 0, used = 0;
    if (dna_env_encoded_size(&leg, 1, &len) != 0) return -1;
    uint8_t *bytes = malloc(len);
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    int ok = -1;
    do {
        if (!bytes || !pf) break;
        if (dna_env_encode(&in, bytes, len, &used) != 0 || used != len) break;
        if (dna_env_preflight(bytes, len, w->v2_chain32, height, &lctx, 1,
                              pf) != DNA_ENV_PF_OK)
            break;
        size_t sl = 0;
        auth[0] = 1;
        memcpy(auth + 1, g_k[signer].pk, PK_LEN);
        if (qgp_dsa87_sign(auth + 1 + PK_LEN, &sl, pf->auth_digest[0], 64,
                           g_k[signer].sk) != 0)
            break;
        if (dna_env_encode(&in, bytes, len, &used) != 0 || used != len) break;
        ok = 0;
    } while (0);
    free(pf);
    if (ok != 0) { free(bytes); return -1; }
    *out = bytes;
    *out_len = len;
    return 0;
}

/* Every validator seat's report for epoch H, built at height `h`, with
 * EVERY member bit set (bitmap_len = ceil(count / 8) — 0 for an empty
 * set). envs[0..N_VAL). */
static nodus_storage_set_t g_set_r;

static int reports_all(fixture_t *fx, uint64_t h, uint64_t H,
                       uint8_t **envs, size_t *lens) {
    nodus_storage_set_t *s = &g_set_r;
    if (nodus_witness_storage_set_get(fx->w, H, s) != 0) return -1;
    dna_vset_snapshot_t *snap = NULL;
    if (nodus_witness_v2_epoch_authority_for_epoch(fx->w, H, &snap, NULL,
                                                   NULL) != 0 || !snap)
        return -1;
    int ret = 0;
    for (int vk = 0; vk < N_VAL && ret == 0; vk++) {
        uint32_t seat = UINT32_MAX;
        for (uint32_t x = 0; x < snap->active_count; x++)
            if (memcmp(snap->entries[x].pubkey, g_k[vk].pk, PK_LEN) == 0)
                seat = x;
        if (seat == UINT32_MAX) { ret = -1; break; }
        uint8_t bm[32], call[REP_FIXED + 32];
        memset(bm, 0, sizeof(bm));
        const uint16_t bl = (uint16_t)((s->count + 7u) / 8u);
        for (uint32_t i = 0; i < s->count; i++)
            bm[i / 8u] |= (uint8_t)(1u << (i % 8u));
        uint32_t cl = rep_call(call, H, seat, s->set_hash, bm, bl);
        if (rep_env(fx->w, h, call, cl, vk, &envs[vk], &lens[vk]) != 0)
            ret = -1;
    }
    dna_vset_free(&snap);
    return ret;
}

/* ══ observations ══════════════════════════════════════════════════════ */

static int accrual_of(nodus_witness_t *w, const uint8_t fp[64],
                      uint64_t *out) {
    sqlite3_stmt *st = NULL;
    *out = 0;
    if (sqlite3_prepare_v2(w->db, "SELECT amount FROM v2_reward_accrual "
                           "WHERE owner_fp = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, fp, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) *out = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return (rc == SQLITE_ROW || rc == SQLITE_DONE) ? 0 : -1;
}

static int pool1_of(nodus_witness_t *w, uint64_t *out) {
    return q_u64(w, "SELECT balance FROM v2_treasury WHERE pool_id = 1",
                 out);
}

static int streak_of(nodus_witness_t *w, const uint8_t fp[64],
                     uint32_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "SELECT fail_streak FROM v2_storage_nodes "
                           "WHERE node_fp = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, fp, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    int ret = -1;
    if (rc == SQLITE_ROW) {
        *out = (uint32_t)sqlite3_column_int64(st, 0);
        ret = 0;
    }
    sqlite3_finalize(st);
    return ret;
}

static int grace_of(nodus_witness_t *w, const uint8_t fp[64],
                    uint64_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "SELECT grace_until FROM v2_storage_nodes "
                           "WHERE node_fp = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, fp, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    int ret = -1;
    if (rc == SQLITE_ROW &&
        sqlite3_column_type(st, 0) == SQLITE_INTEGER &&
        sqlite3_column_int64(st, 0) >= 0) {
        *out = (uint64_t)sqlite3_column_int64(st, 0);
        ret = 0;
    }
    sqlite3_finalize(st);
    return ret;
}

/* Σ amount of the UTXOs owned by KM's hex fingerprint. */
static int km_utxo_sum(nodus_witness_t *w, uint64_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "SELECT COALESCE(SUM(amount), 0) FROM "
                           "utxo_set WHERE owner = ?1", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, g_k[KM].hex, 128, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_int64 v = rc == SQLITE_ROW ? sqlite3_column_int64(st, 0) : -1;
    sqlite3_finalize(st);
    if (rc != SQLITE_ROW || v < 0) return -1;
    *out = (uint64_t)v;
    return 0;
}

static int core_invariant(nodus_witness_t *w) {
    const nodus_domain_runtime_t *rt = NULL;
    if (nodus_witness_v2_runtime_for(w, DNA_DOMAIN_CORE, 1, &rt) != 0 || !rt
        || !rt->invariant)
        return -1;
    return rt->invariant(rt, w);
}

/* ══ the zero-member boundary check ════════════════════════════════════ */

/* S(H) for an EMPTY set, restated from bytes §2 (2026-10-04-storage-
 * reward-bytes.md): SHA3-512("NDS.STSET.v1" zero-padded to 16 ‖ H u64 BE
 * ‖ count u32 BE = 0) — the padding convention of the archive KAT's tag
 * section (archive_reward_kat.json "tags"). */
static int empty_set_hash(uint64_t B, uint8_t out[64]) {
    uint8_t pre[16 + 8 + 4];
    memset(pre, 0, sizeof(pre));
    memcpy(pre, "NDS.STSET.v1", 12);
    put64(pre + 16, B);
    put32(pre + 24, 0);
    return qgp_sha3_512(pre, sizeof(pre), out);
}

static uint64_t g_empty_last;     /* boundaries <= this have no member */
static uint64_t g_empty_seen;     /* boundary checks run (both twins)  */
static nodus_storage_set_t g_set_e;

#define ECHK(cond, what) do { if (!(cond)) { \
    fprintf(stderr, "empty boundary %llu: %s\n", (unsigned long long)B, \
            (what)); return -1; } g_checks++; } while (0)

static int empty_boundary(nodus_witness_t *w, uint64_t B) {
    if (B > g_empty_last) return 0;
    uint8_t lib[64], own[64];
    uint64_t n = 0, p1 = 0, acc = 0;
    ECHK(nodus_witness_storage_set_get(w, B, &g_set_e) == 0,
         "storage_set(B) exists (rc 0, not absent)");
    ECHK(g_set_e.count == 0, "storage_set(B) has no member");
    ECHK(dna_v2_storage_set_hash(B, NULL, 0, lib) == 0 &&
         empty_set_hash(B, own) == 0 && memcmp(lib, own, 64) == 0,
         "dna_v2_storage_set_hash(B, NULL, 0) == bytes §2 restated");
    ECHK(memcmp(g_set_e.set_hash, own, 64) == 0,
         "stored S(B) == the empty-set S(B)");
    {
        sqlite3_stmt *st = NULL;
        ECHK(sqlite3_prepare_v2(w->db, "SELECT member_count FROM "
                                "v2_storage_sets WHERE epoch_start = ?1",
                                -1, &st, NULL) == SQLITE_OK, "prepare");
        sqlite3_bind_int64(st, 1, (sqlite3_int64)B);
        int ok = sqlite3_step(st) == SQLITE_ROW &&
                 sqlite3_column_type(st, 0) == SQLITE_INTEGER &&
                 sqlite3_column_int64(st, 0) == 0;
        sqlite3_finalize(st);
        ECHK(ok, "the header row says member_count 0");
    }
    ECHK(q_u64(w, "SELECT COUNT(*) FROM v2_storage_set_members", &n) == 0 &&
         n == 0, "no member row at all");
    {
        const uint64_t j = B / E_LEN, want = j < 3 ? j : 3;
        ECHK(q_u64(w, "SELECT COUNT(*) FROM v2_storage_sets", &n) == 0 &&
             n == want, "set headers kept = min(B/E, 3) (prune keeps "
             "set(B-2E) .. set(B))");
    }
    ECHK(q_u64(w, "SELECT COUNT(*) FROM v2_storage_nodes", &n) == 0 &&
         n == 0, "no registry row");
    ECHK(pool1_of(w, &p1) == 0 && p1 == POOL1,
         "pool 1 untouched (no storage debit)");
    ECHK(accrual_of(w, g_k[KM].fp, &acc) == 0 && acc == 0,
         "no storage accrual");
    ECHK(core_invariant(w) == 0, "the CORE invariant holds");
    g_empty_seen++;
    return 0;
}

static void votes_init(void) {
    for (int i = 0; i < N_VAL; i++) {
        memcpy(g_vaddr[i], g_k[i].fp, 32);
        g_vflag[i] = CMT_PB_BLOCK_ID_FLAG_COMMIT;
    }
}

/* ══ case 1: empty chain → zero-member payday → first member ═══════════ */

static nodus_storage_set_t g_set_a;

static int t_empty_then_first(void) {
    fixture_t A, B;
    uint64_t h = 0, n = 0, iv = 0;
    uint32_t codes[8];
    uint8_t *e[8] = { NULL };
    size_t l[8] = { 0 };

    CHECK(E_LEN >= 8, "no epoch boundary among heights 1..7");
    CHECK(P_LEN == 24 * E_LEN, "a segment is 24 epochs");
    votes_init();
    CHECK(coin_nul(g_nul) == 0, "coin nullifier");
    CHECK(fx_open(&A, "a1", 0) == 0 && fx_open(&B, "b1", 0) == 0,
          "twin seeded chains (real committee, pool 1, no segment)");
    CHECK(nodus_witness_v2_payout_interval(A.w, &iv) == 0 && iv > 0,
          "the chain's payout interval");
    const uint64_t PAY = iv * E_LEN;
    CHECK(PAY <= 25 * E_LEN, "the payday falls inside the empty stretch "
          "(interval <= 25 epochs)");

    g_hook = empty_boundary;
    g_empty_last = 25 * E_LEN;
    g_empty_seen = 0;

    /* boundaries E, 2E: an empty set frozen at each */
    CHECK(run_idle(&A, &B, &h, 2 * E_LEN) == 0,
          "to 2E (each boundary: the zero-member check, both twins)");
    CHECK(g_empty_seen == 4, "boundaries E and 2E checked on both twins");

    /* 2E + 1: all seven seats report for H = E against the EMPTY set */
    CHECK(reports_all(&A, 2 * E_LEN + 1, E_LEN, e, l) == 0,
          "seven reports for H = E, bitmap_len 0");
    CHECK(submit(&A, &B, 2 * E_LEN + 1, e, l, N_VAL, codes) == 0, "2E+1");
    for (int i = 0; i < N_VAL; i++)
        CHECK(codes[i] == NODUS_V2_TX_OK,
              "a report against an empty set applies (ceil(0/8) = 0)");
    h = 2 * E_LEN + 1;
    CHECK(q_u64(A.w, "SELECT COUNT(*) FROM v2_storage_reports WHERE "
                "typeof(bitmap) = 'blob' AND length(bitmap) = 0", &n) == 0 &&
          n == N_VAL, "seven committed reports, each an EMPTY blob");

    /* boundary 3E: settle H = E — F1 met (7/7 power), zero members */
    CHECK(run_idle(&A, &B, &h, 3 * E_LEN) == 0,
          "boundary 3E: settlement over an empty set with F1 met");
    CHECK(q_u64(A.w, "SELECT COUNT(*) FROM v2_storage_reports", &n) == 0 &&
          n == 0, "the reports for H = E are pruned");

    /* the payday with zero members — it must have rows to pay (the
     * validators' distribution), or crossing it proves nothing */
    CHECK(run_idle(&A, &B, &h, PAY - 1) == 0, "to the payday - 1 (every "
          "boundary on the way: the zero-member check)");
    CHECK(q_u64(A.w, "SELECT COUNT(*) FROM v2_reward_accrual", &n) == 0 &&
          n > 0, "before the payday: validator accrual rows exist");
    CHECK(run_idle(&A, &B, &h, PAY) == 0, "the payday boundary");
    CHECK(q_u64(A.w, "SELECT COUNT(*) FROM v2_reward_accrual", &n) == 0 &&
          n == 0, "payday: every accrual row paid out");
    CHECK(core_invariant(A.w) == 0 && core_invariant(B.w) == 0,
          "payday with zero storage members: the CORE invariant holds on "
          "both twins");

    /* to 25E: still empty; KM registers at 25E + 5 */
    CHECK(run_idle(&A, &B, &h, 25 * E_LEN + 4) == 0, "to 25E+4");
    CHECK(g_empty_seen == 2 * 25, "25 empty boundaries checked on both "
          "twins");
    CHECK(reg_env(A.w, 25 * E_LEN + 5, &e[0], &l[0]) == 0,
          "KM's registration envelope");
    CHECK(submit(&A, &B, 25 * E_LEN + 5, e, l, 1, codes) == 0 &&
          codes[0] == NODUS_V2_TX_OK,
          "KM registers after 25 empty boundaries");
    h = 25 * E_LEN + 5;

    /* boundary 26E: k = 1 published by the chain AND KM enters the set */
    CHECK(run_idle(&A, &B, &h, 26 * E_LEN) == 0, "boundary 26E");
    CHECK(q_u64(A.w, "SELECT COUNT(*) FROM v2_storage_segments", &n) == 0 &&
          n == 1, "exactly one segment published");
    CHECK(q_u64(A.w, "SELECT published_height FROM v2_storage_segments "
                "WHERE k = 1", &n) == 0 && n == P_LEN + 2 * E_LEN &&
          n == 26 * E_LEN, "k = 1 published at P + 2E = 26E");
    {
        uint8_t got[64], want[64];
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(A.w->db, "SELECT root FROM "
              "v2_storage_segments WHERE k = 1", -1, &st, NULL) == SQLITE_OK,
              "prepare");
        int ok = sqlite3_step(st) == SQLITE_ROW &&
                 sqlite3_column_bytes(st, 0) == 64;
        if (ok) memcpy(got, sqlite3_column_blob(st, 0), 64);
        sqlite3_finalize(st);
        CHECK(ok && nodus_witness_storage_segment_root_compute(A.w, 1, want)
              == 0 && memcmp(got, want, 64) == 0,
              "Root(1) == the root over v2_blocks 1..P");
    }
    CHECK(nodus_witness_storage_set_get(A.w, 25 * E_LEN, &g_set_a) == 0 &&
          g_set_a.count == 0, "set(25E) exists and is empty");
    CHECK(nodus_witness_storage_set_get(A.w, 26 * E_LEN, &g_set_a) == 0 &&
          g_set_a.count == 1 && memcmp(g_set_a.fps[0], g_k[KM].fp, 64) == 0,
          "KM enters set(26E)");
    {
        /* K9a, restated: k = 1 is published at 26E > 26E − E → n = 0 */
        const uint64_t H = 26 * E_LEN, pub = 26 * E_LEN;
        const uint64_t n_own = (pub <= H - E_LEN) ? 1u : 0u;
        uint64_t reg = 1;
        CHECK(n_own == 0 && nodus_storage_grace_counts(H, E_LEN, pub, 1, 1,
                                                       0) == 0,
              "K9a: a segment published AT the entry boundary counts 0");
        CHECK(g_set_a.grace_until[0] == 0, "frozen grace_until 0");
        CHECK(grace_of(A.w, g_k[KM].fp, &reg) == 0 && reg == 0,
              "registry grace_until 0");
    }
    {
        uint64_t ks[MAX_SEGS];
        size_t nk = MAX_SEGS + 1;
        CHECK(nodus_witness_storage_eligible_segments(A.w, 26 * E_LEN,
                                                      g_k[KM].fp, ks,
                                                      MAX_SEGS, &nk) == 0 &&
              nk == 1 && ks[0] == 1,
              "KM is probed at once on k = 1 (no grace)");
    }

    /* 27E + 1: all seven report for H = 26E, KM's bit 1 */
    CHECK(run_idle(&A, &B, &h, 27 * E_LEN) == 0, "boundary 27E");
    CHECK(reports_all(&A, 27 * E_LEN + 1, 26 * E_LEN, e, l) == 0,
          "seven reports for H = 26E");
    CHECK(submit(&A, &B, 27 * E_LEN + 1, e, l, N_VAL, codes) == 0, "27E+1");
    for (int i = 0; i < N_VAL; i++)
        CHECK(codes[i] == NODUS_V2_TX_OK, "report applies");
    h = 27 * E_LEN + 1;

    /* boundary 28E: settle H = 26E — KM alone, weight P */
    uint64_t p0 = 0, p1 = 0, a0 = 0, a1 = 0;
    uint32_t s1 = 99;
    CHECK(run_idle(&A, &B, &h, 28 * E_LEN - 1) == 0, "to 28E-1");
    CHECK(pool1_of(A.w, &p0) == 0 && accrual_of(A.w, g_k[KM].fp, &a0) == 0,
          "before 28E");
    CHECK(p0 == POOL1 && a0 == 0, "nothing paid to storage yet");
    CHECK(run_idle(&A, &B, &h, 28 * E_LEN) == 0, "boundary 28E");
    CHECK(pool1_of(A.w, &p1) == 0 && accrual_of(A.w, g_k[KM].fp, &a1) == 0 &&
          streak_of(A.w, g_k[KM].fp, &s1) == 0, "after 28E");
    {
        const uint64_t budget = p0 >> NODUS_V2_GEN_REWARD_DIVISOR_LOG2;
        CHECK(budget > 0 && a1 - a0 == budget,
              "KM credited floor(budget · P / P) = pool1 >> 16");
        CHECK(p0 - p1 == budget, "pool 1 debited exactly the credit");
        CHECK(s1 == 0, "OK with weight: fail_streak 0");
    }
    CHECK(core_invariant(A.w) == 0 && core_invariant(B.w) == 0,
          "the CORE invariant holds on both twins");

    g_hook = NULL;
    fx_close(&A);
    fx_close(&B);
    return 0;
}

/* ══ the 0x73 code 6 (FAULT) over fixture A's end state ════════════════ */

static int sql_ok(nodus_witness_t *w, const char *sql) {
    return v2x_sql(w->db, sql);
}

static int t_fetch_fault(nodus_witness_t *w, uint64_t tip) {
    uint8_t *out = malloc(NODUS_STFETCH_MSG_MAX);
    size_t len = 7;
    char sql[256];
    CHECK(out != NULL, "alloc");
    const uint64_t H = (tip / E_LEN) * E_LEN;
    nodus_stfetch_req_t r = { 1, 1, 0, NODUS_STFETCH_CONT_FIRST };
#define SERVE() nodus_witness_stfetch_serve(w, NULL, NULL, g_k[KM].fp, &r, \
                                            E_LEN, out,                    \
                                            NODUS_STFETCH_MSG_MAX, &len)
    CHECK(SERVE() == NODUS_STFETCH_REF_NOT_HELD && len == 0,
          "baseline: KM admitted, k = 1 published, nothing held here");

    /* (1) a stored S(H) that does not re-derive from its members */
    uint8_t saved[64];
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(w->db, "SELECT set_hash FROM v2_storage_sets "
              "WHERE epoch_start = ?1", -1, &st, NULL) == SQLITE_OK,
              "prepare");
        sqlite3_bind_int64(st, 1, (sqlite3_int64)H);
        int ok = sqlite3_step(st) == SQLITE_ROW &&
                 sqlite3_column_bytes(st, 0) == 64;
        if (ok) memcpy(saved, sqlite3_column_blob(st, 0), 64);
        sqlite3_finalize(st);
        CHECK(ok, "S(H) of the current set");
    }
    snprintf(sql, sizeof(sql), "UPDATE v2_storage_sets SET set_hash = "
             "zeroblob(64) WHERE epoch_start = %llu", (unsigned long long)H);
    CHECK(sql_ok(w, sql) == 0, "corrupt S(H)");
    CHECK(SERVE() == NODUS_STFETCH_REF_FAULT && len == 0,
          "S(H) does not re-derive: code 6 FAULT");
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(w->db, "UPDATE v2_storage_sets SET "
              "set_hash = ?1 WHERE epoch_start = ?2", -1, &st, NULL)
              == SQLITE_OK, "prepare");
        sqlite3_bind_blob(st, 1, saved, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)H);
        int ok = sqlite3_step(st) == SQLITE_DONE;
        sqlite3_finalize(st);
        CHECK(ok, "restore S(H)");
    }
    CHECK(SERVE() == NODUS_STFETCH_REF_NOT_HELD, "restored: NOT_HELD again");

    /* (2) member_count disagrees with the member rows */
    snprintf(sql, sizeof(sql), "UPDATE v2_storage_sets SET member_count = 2 "
             "WHERE epoch_start = %llu", (unsigned long long)H);
    CHECK(sql_ok(w, sql) == 0, "member_count 2 over one member row");
    CHECK(SERVE() == NODUS_STFETCH_REF_FAULT,
          "a member count that disagrees: code 6 FAULT");
    snprintf(sql, sizeof(sql), "UPDATE v2_storage_sets SET member_count = 1 "
             "WHERE epoch_start = %llu", (unsigned long long)H);
    CHECK(sql_ok(w, sql) == 0, "restore member_count");
    CHECK(SERVE() == NODUS_STFETCH_REF_NOT_HELD, "restored: NOT_HELD again");

    /* (3) the registry unreadable */
    CHECK(sql_ok(w, "ALTER TABLE v2_storage_nodes RENAME TO t_nodes") == 0,
          "hide the registry");
    CHECK(SERVE() == NODUS_STFETCH_REF_FAULT,
          "registry read fails: code 6 FAULT, not NOT_MEMBER");
    CHECK(sql_ok(w, "ALTER TABLE t_nodes RENAME TO v2_storage_nodes") == 0,
          "restore the registry");
    CHECK(SERVE() == NODUS_STFETCH_REF_NOT_HELD, "restored: NOT_HELD again");

    /* (4) the segment list unreadable */
    CHECK(sql_ok(w, "ALTER TABLE v2_storage_segments RENAME TO t_segs") == 0,
          "hide the segment list");
    CHECK(SERVE() == NODUS_STFETCH_REF_FAULT,
          "segment list read fails: code 6 FAULT, not NOT_PUBLISHED");
    CHECK(sql_ok(w, "ALTER TABLE t_segs RENAME TO v2_storage_segments") == 0,
          "restore the segment list");
    CHECK(SERVE() == NODUS_STFETCH_REF_NOT_HELD, "restored: NOT_HELD again");

    /* (5) the tip unreadable */
    CHECK(sql_ok(w, "ALTER TABLE v2_blocks RENAME TO t_blocks") == 0,
          "hide v2_blocks");
    CHECK(SERVE() == NODUS_STFETCH_REF_FAULT,
          "tip read fails: code 6 FAULT, not UNKNOWN_SET");
    CHECK(sql_ok(w, "ALTER TABLE t_blocks RENAME TO v2_blocks") == 0,
          "restore v2_blocks");
    CHECK(SERVE() == NODUS_STFETCH_REF_NOT_HELD, "restored: NOT_HELD again");
#undef SERVE

    /* (6) the piece builder: an invalid request is FAULT, never OK */
    {
        nodus_stfetch_req_t bad = { 0, 1, 0, NODUS_STFETCH_CONT_FIRST };
        len = 7;
        CHECK(nodus_stfetch_answer_build(NULL, NULL, &bad, out,
                                         NODUS_STFETCH_MSG_MAX, &len) ==
              NODUS_STFETCH_REF_FAULT, "k = 0: code 6 FAULT");
        bad = r;
        bad.cont = 2;
        CHECK(nodus_stfetch_answer_build(NULL, NULL, &bad, out,
                                         NODUS_STFETCH_MSG_MAX, &len) ==
              NODUS_STFETCH_REF_FAULT, "cont 2: code 6 FAULT");
    }

    /* (7) the code-6 refusal on the wire, and the receiving client */
    {
        uint8_t rq[64], ref[NODUS_STFETCH_REFUSAL_LEN];
        nodus_stfetch_ans_view_t a;
        CHECK(nodus_stfetch_req_id(&r, rq) == 0 &&
              nodus_stfetch_ans_refusal(rq, NODUS_STFETCH_REF_FAULT, ref)
              == 0, "the code-6 refusal");
        CHECK(ref[0] == NODUS_STFETCH_KIND_ANS && memcmp(ref + 1, rq, 64)
              == 0 && ref[65] == 6, "kind ‖ rq ‖ 6, 66 bytes");
        CHECK(nodus_stfetch_ans_decode(ref, sizeof(ref), &a) == 0 &&
              a.code == NODUS_STFETCH_REF_FAULT && memcmp(a.rq, rq, 64) == 0,
              "it decodes as code 6");
        CHECK(!nodus_stfetch_ans_shape_ok(&r, &a),
              "a code-6 answer is never an OK shape");
        CHECK(nodus_stfetch_ans_decode(ref, sizeof(ref) - 1, &a) != 0,
              "a refusal one byte short does not decode");
        CHECK(nodus_witness_sthold_on_msg(w, "peer-without-request",
                                          g_k[V1].fp, ref, sizeof(ref)) == 0,
              "an answer with no outstanding request is dropped (0)");
        uint8_t junk[4] = { 0x09, 0, 0, 0 };
        CHECK(nodus_witness_sthold_on_msg(w, "peer-without-request",
                                          g_k[V1].fp, junk, sizeof(junk))
              == -1, "an undecodable 0x73 message is refused (-1)");
        CHECK(nodus_witness_sthold_on_msg(w, "peer-without-request",
                                          g_k[V1].fp, ref, sizeof(ref) - 1)
              == -1, "a truncated answer is refused (-1)");
    }
    free(out);
    return 0;
}

/* ══ case 2: first member after empty boundaries → payday with one ═════ */

static int t_first_member_payday(void) {
    fixture_t A, B;
    uint64_t h = 0, n = 0, iv = 0;
    uint32_t codes[8];
    uint8_t *e[8] = { NULL };
    size_t l[8] = { 0 };

    CHECK(E_LEN >= 8, "no epoch boundary among heights 1..7");
    votes_init();
    CHECK(coin_nul(g_nul) == 0, "coin nullifier");
    CHECK(fx_open(&A, "a2", MAX_SEGS) == 0 &&
          fx_open(&B, "b2", MAX_SEGS) == 0,
          "twin seeded chains (real committee, pool 1, segments 1..8)");
    CHECK(nodus_witness_v2_payout_interval(A.w, &iv) == 0 && iv > 0,
          "the chain's payout interval");
    const uint64_t PAY = iv * E_LEN;
    CHECK(PAY >= 15 * E_LEN, "the payday falls after the credit at 14E");

    g_hook = empty_boundary;
    g_empty_last = 3 * E_LEN;
    g_empty_seen = 0;

    CHECK(run_idle(&A, &B, &h, 3 * E_LEN + 4) == 0,
          "to 3E+4 (boundaries E, 2E, 3E empty)");
    CHECK(g_empty_seen == 2 * 3, "three empty boundaries, both twins");
    CHECK(reg_env(A.w, 3 * E_LEN + 5, &e[0], &l[0]) == 0,
          "KM's registration envelope");
    CHECK(submit(&A, &B, 3 * E_LEN + 5, e, l, 1, codes) == 0 &&
          codes[0] == NODUS_V2_TX_OK,
          "KM registers after three empty boundaries");
    h = 3 * E_LEN + 5;

    /* boundary 4E: KM enters; set(3E) exists (empty) — the test's own
     * K9a count over the eight pre-existing segments */
    CHECK(run_idle(&A, &B, &h, 4 * E_LEN) == 0, "boundary 4E");
    CHECK(nodus_witness_storage_set_get(A.w, 3 * E_LEN, &g_set_a) == 0 &&
          g_set_a.count == 0, "set(3E) exists and is empty");
    CHECK(nodus_witness_storage_set_get(A.w, 4 * E_LEN, &g_set_a) == 0 &&
          g_set_a.count == 1 && memcmp(g_set_a.fps[0], g_k[KM].fp, 64) == 0,
          "set(4E) = {KM}");
    uint64_t n_new = 0;
    for (uint64_t k = 1; k <= MAX_SEGS; k++) {
        uint8_t r[64], hf[DNA_V2_STORAGE_HOLDERS][64];
        size_t nh = 0;
        int holds = 0;
        CHECK(seg_root(k, r) == 0 &&
              nodus_witness_storage_holders(&g_set_a, r, hf, &nh) == 0,
              "holders over set(4E)");
        for (size_t j = 0; j < nh; j++)
            if (memcmp(hf[j], g_k[KM].fp, 64) == 0) holds = 1;
        /* published 1 <= 4E − E; held now; set(3E) empty: not held then */
        if (holds && (uint64_t)1 <= 4 * E_LEN - E_LEN) n_new++;
    }
    CHECK(n_new == MAX_SEGS, "the sole member holds all eight segments");
    const uint64_t G = 4 * E_LEN + n_new * E_LEN;
    {
        uint64_t reg = 0;
        CHECK(g_set_a.grace_until[0] == G,
              "frozen grace_until = 4E + n·E (K9, K9a: set(3E) exists)");
        CHECK(grace_of(A.w, g_k[KM].fp, &reg) == 0 && reg == G,
              "registry grace_until = 4E + n·E");
    }

    /* boundaries 4E .. G: no eligible segment while H < G, all at G */
    for (uint64_t B_ = 4 * E_LEN; B_ <= G; B_ += E_LEN) {
        uint64_t ks[MAX_SEGS], reg = 0;
        size_t nk = MAX_SEGS + 1;
        CHECK(run_idle(&A, &B, &h, B_) == 0, "to the next boundary");
        CHECK(nodus_witness_storage_set_get(A.w, B_, &g_set_a) == 0 &&
              g_set_a.count == 1 && g_set_a.grace_until[0] == G,
              "frozen grace_until stays G (n = 0 once held)");
        CHECK(grace_of(A.w, g_k[KM].fp, &reg) == 0 && reg == G,
              "registry grace_until stays G");
        CHECK(nodus_witness_storage_eligible_segments(A.w, B_, g_k[KM].fp,
                                                      ks, MAX_SEGS, &nk)
              == 0, "eligibility read");
        if (B_ < G) {
            CHECK(nk == 0, "in grace: no eligible segment");
        } else {
            CHECK(nk == MAX_SEGS, "grace over: all eight eligible");
            for (size_t i = 0; i < nk; i++)
                CHECK(ks[i] == (uint64_t)i + 1, "k ascending 1..8");
        }
    }

    /* G + E + 1: reports for H = G; boundary G + 2E settles it */
    CHECK(run_idle(&A, &B, &h, G + E_LEN) == 0, "to G+E");
    CHECK(reports_all(&A, G + E_LEN + 1, G, e, l) == 0,
          "seven reports for H = G");
    CHECK(submit(&A, &B, G + E_LEN + 1, e, l, N_VAL, codes) == 0, "G+E+1");
    for (int i = 0; i < N_VAL; i++)
        CHECK(codes[i] == NODUS_V2_TX_OK, "report applies");
    h = G + E_LEN + 1;
    uint64_t p0 = 0, p1 = 0, a0 = 0, a1 = 0;
    uint32_t s1 = 99;
    CHECK(run_idle(&A, &B, &h, G + 2 * E_LEN - 1) == 0, "to G+2E-1");
    CHECK(pool1_of(A.w, &p0) == 0 && accrual_of(A.w, g_k[KM].fp, &a0) == 0 &&
          p0 == POOL1 && a0 == 0, "before G+2E: nothing paid to storage");
    CHECK(run_idle(&A, &B, &h, G + 2 * E_LEN) == 0, "boundary G+2E");
    CHECK(pool1_of(A.w, &p1) == 0 && accrual_of(A.w, g_k[KM].fp, &a1) == 0 &&
          streak_of(A.w, g_k[KM].fp, &s1) == 0, "after G+2E");
    const uint64_t budget = p0 >> NODUS_V2_GEN_REWARD_DIVISOR_LOG2;
    CHECK(budget > 0 && a1 == budget,
          "KM credited the whole budget (sole weight 8P of 8P)");
    CHECK(p0 - p1 == budget, "pool 1 debited exactly the credit");
    CHECK(s1 == 0, "fail_streak 0");
    CHECK(G + 2 * E_LEN < PAY, "the credit lands before the payday");

    /* the payday with one member holding storage credit */
    uint64_t acc0 = 0, u0 = 0, u1 = 0, pp0 = 0, pp1 = 0;
    CHECK(run_idle(&A, &B, &h, PAY - 1) == 0, "to the payday - 1");
    CHECK(accrual_of(A.w, g_k[KM].fp, &acc0) == 0 && acc0 == budget,
          "KM's accrual = its storage credit (no other source)");
    CHECK(km_utxo_sum(A.w, &u0) == 0 && u0 == 0,
          "KM owns no UTXO (its coin funded the bond)");
    CHECK(pool1_of(A.w, &pp0) == 0, "pool 1 before the payday");
    CHECK(run_idle(&A, &B, &h, PAY) == 0, "the payday boundary");
    CHECK(km_utxo_sum(A.w, &u1) == 0 && u1 == acc0,
          "payday: KM's accrual became its spendable UTXO value");
    CHECK(q_u64(A.w, "SELECT COUNT(*) FROM v2_reward_accrual", &n) == 0 &&
          n == 0, "payday: every accrual row paid out");
    CHECK(pool1_of(A.w, &pp1) == 0 && pp1 == pp0,
          "pool 1 untouched at the payday (no settlement: no report)");
    CHECK(core_invariant(A.w) == 0 && core_invariant(B.w) == 0,
          "payday with one storage member: the CORE invariant holds on "
          "both twins");
    {
        uint64_t u1b = 0;
        CHECK(km_utxo_sum(B.w, &u1b) == 0 && u1b == u1,
              "twin B paid KM the same");
    }

    g_hook = NULL;
    /* the 0x73 code 6 over fixture A's end state (B is not touched) */
    if (t_fetch_fault(A.w, h) != 0) {
        fx_close(&A);
        fx_close(&B);
        return 1;
    }
    fx_close(&A);
    fx_close(&B);
    return 0;
}

int main(void) {
    static const struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        { "empty_chain_then_first_member", t_empty_then_first },
        { "first_member_then_payday",      t_first_member_payday },
    };
    size_t failed = 0, n = sizeof(cases) / sizeof(cases[0]);
    if (keys_make() != 0) {
        fprintf(stderr, "test_storage_empty: key generation failed\n");
        return 1;
    }
    for (size_t i = 0; i < n; i++) {
        int rc = cases[i].fn();
        fprintf(stderr, "%-30s %s\n", cases[i].name, rc == 0 ? "ok" : "FAIL");
        if (rc != 0) failed++;
    }
    fprintf(stderr, "test_storage_empty: %zu/%zu cases passed, %d checks\n",
            n - failed, n, g_checks);
    return failed ? 1 : 0;
}
