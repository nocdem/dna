/**
 * Nodus — O15J Faz 2: V1's economics on the Ledger V2 lane
 * (nodus_witness_v2_econ.{h,c}), driven through the REAL apply engine.
 *
 * Sections:
 *   §1  EMISSION GATE — a block mints exactly nodus_emission_per_block(h)
 *       into BOTH total_minted and epoch_pool_accum; an
 *       INFLATION_START_BLOCK override of 0 disables emission entirely;
 *       an override of K mints nothing below K and everything from K on.
 *   §2  EPOCH-START SNAPSHOT — the first mint of an epoch writes the
 *       epoch_state row AND its committee+delegation snapshot; the blob
 *       carries the committee this epoch actually has, with each seat's
 *       real bond, and the stored hash commits those exact bytes.
 *   §3  SETTLEMENT, NO DELEGATIONS — at the first boundary the whole
 *       epoch-0 pool splits per_slot to each committee member as a CORE
 *       UTXO at an INDEPENDENTLY recomputed identity, the indivisible
 *       remainder is BURNED (burn leg 1 of 3), and the settled epoch row
 *       is retired while the boundary block's own mint seeds the next.
 *   §4  SETTLEMENT, WITH DELEGATIONS — validator_base / commission /
 *       per-delegator share are each pinned to the V1 formula, and the
 *       integer-division remainder of the delegator split is BURNED
 *       (burn leg 3 of 3, made STRUCTURALLY NON-ZERO — see the DELS
 *       comment — so a dropped leg cannot hide behind a zero).
 *   §5  OFFLINE SHARE — in a NON-carve-out epoch a member that did not
 *       clear the liveness bar is paid NOTHING and its whole slot is
 *       BURNED (burn leg 2 of 3), while a member that did clear it is
 *       paid in full. Attendance is accumulated through the REAL O15C
 *       writer by proposing real blocks — nothing is hand-written. This
 *       is also what pins the settlement-before-Rule-N ordering: Rule N
 *       resets the very counter the liveness gate reads.
 *   §6  SUPPLY EQUATION — recomputed term by term from the tables (not
 *       merely by asking the gate) at every stage of every cycle above.
 *   §7  DETERMINISM TWIN — two independent fixtures seeded in OPPOSITE
 *       validator order, driven through a full emission+settlement
 *       cycle, produce byte-identical SYSTEM and CORE state roots.
 *
 * ── ANTI-VACUITY ────────────────────────────────────────────────────
 * Every assertion names the mutation that kills it, at the assertion.
 * Where a property is defended by TWO independent guards a single mutant
 * SURVIVES, and the compound mutant is named instead — reporting such a
 * survival as "not covered" is the error this season already paid for
 * once. Three assertions here also guard the FIXTURE against becoming
 * vacuous (a commission that rounds to zero, an inner dust that happens
 * to be zero, a liveness bar outside the epoch): each fails loudly and
 * tells the maintainer to pick different numbers.
 *
 * Copyright (c) 2026 nocdem — SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_emission.h"
#include "witness/nodus_witness_epoch.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_econ.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "witness/nodus_witness_v2_schema.h"   /* migrate_v2s9 */
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_delegation.h"
#include "witness/nodus_witness_vset.h"
#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_types.h"
#include "dnac/dnac.h"
#include "dnac/ledger_ids.h"
#include "dnac/validator.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_fingerprint.h"

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
 * ZERO envelopes, so no signature is ever verified. The tables only need
 * DISTINCT 2592-byte pubkeys. */
#define N_KEYS 10
static uint8_t g_pk[N_KEYS][DNAC_PUBKEY_SIZE];
static char    g_fp[N_KEYS][129];

static void keys_init(void) {
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < N_KEYS; i++) {
        for (int b = 0; b < DNAC_PUBKEY_SIZE; b++)
            g_pk[i][b] = (uint8_t)((b * 31u + i * 7u + 11u) & 0xFF);
        g_pk[i][0] = (uint8_t)(0x10 + i);
        uint8_t full[64];
        qgp_sha3_512(g_pk[i], DNAC_PUBKEY_SIZE, full);
        for (int b = 0; b < 64; b++) {
            g_fp[i][2 * b]     = hexd[full[b] >> 4];
            g_fp[i][2 * b + 1] = hexd[full[b] & 0xF];
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

/* Same, with the height/epoch operand FORMATTED from the E macro rather
 * than spelled as a literal: DNAC_EPOCH_LENGTH is #ifndef-guarded for the
 * short-epoch harness, and a hard-coded 720 would silently desynchronize
 * from the chain the fixture actually drives (test_v2_epoch.c:181-185). */
static uint64_t q1f(nodus_witness_t *w, const char *fmt, uint64_t a) {
    char sql[320];
    snprintf(sql, sizeof(sql), fmt, (unsigned long long)a);
    return q1(w, sql);
}

static void mk_id(uint8_t out[64], uint8_t fill) { memset(out, fill, 64); }

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

#define BOND_BASE DNAC_SELF_STAKE_AMOUNT
#define UTXO_A    5000000ULL

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

/* nodus_committee_compute_for_epoch reads the LEGACY `blocks` row at
 * e_start - E - 1 for its state_seed tiebreak; a pure-V2 chain writes no
 * such rows, so the fixture plants the one the source path needs with a
 * FIXED state_root, identical in every fixture so twins agree. The shape
 * is test_v2_epoch.c:339-354, reused rather than re-derived. */
static int seed_legacy_block(fixture_t *fx, uint64_t height) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(fx->w->db,
            "INSERT OR IGNORE INTO blocks (height, tx_root, tx_count, "
            "timestamp, proposer_id, prev_hash, state_root, created_at) "
            "VALUES (?1, zeroblob(64), 0, 0, zeroblob(32), zeroblob(64), "
            "?2, 0)", -1, &st, NULL) != SQLITE_OK)
        return -1;
    uint8_t sr[64];
    memset(sr, 0x5A, sizeof(sr));
    sqlite3_bind_int64(st, 1, (sqlite3_int64)height);
    sqlite3_bind_blob(st, 2, sr, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* One INFLATION_START_BLOCK override, planted BEFORE the V2 genesis:
 * chain_config_history is a leg of system_state_root
 * (nodus_witness_roots_v2.c:265-266), so a post-genesis write would be an
 * out-of-band SYSTEM mutation the untouched-domain guard rejects. */
static int seed_inflation_start(fixture_t *fx, uint64_t value) {
    char sql[320];
    snprintf(sql, sizeof(sql),
             "INSERT INTO chain_config_history (param_id, new_value, "
             "effective_block, commit_block, tx_hash, proposal_nonce, "
             "created_at_unix) VALUES (%d, %llu, 0, 0, zeroblob(64), 0, 0)",
             (int)DNAC_CFG_INFLATION_START_BLOCK,
             (unsigned long long)value);
    if (run_sql(fx->w->db, sql) != 0) return -1;

    /* The chain-config reader keeps a WARM CACHE, and this seeder writes
     * the row with raw SQL — bypassing the mutate path that would
     * invalidate it (the CC-OPS-004 discipline the production
     * CHAIN_CONFIG apply follows, nodus_witness_chain_config.c:1160).
     * Without this line the row is invisible: get_u64 keeps serving the
     * 1ULL default, emission stays ON, and the "explicit 0 disables
     * emission" assertion fails against correct production code. Other
     * tests reach into the same field directly
     * (test_chain_config_cache_failclose.c:154). */
    fx->w->chain_config_cache_warm = false;
    return 0;
}

/* Stage 1: DB + schema + consensus-table seed + the SOURCE genesis vset
 * snapshots. Stops BEFORE the V2 genesis so a test can still shape
 * pre-chain state (the two-stage rule and its reason are spelled out at
 * test_v2_epoch.c:376-400). */
static int fx_stage1(fixture_t *fx, const char *tag,
                     const vspec_t *specs, size_t n_spec,
                     const dspec_t *dels, size_t n_del) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    /* the live constructor's cache sentinel (nodus_witness.c:649) — a
     * zeroed struct would read as a CACHED EMPTY committee for epoch 0 */
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_econ_%s_XXXXXX", tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain_id16, 0x4E, sizeof(fx->chain_id16));
    if (nodus_witness_create_chain_db(fx->w, fx->chain_id16) != 0) return -1;
    if (nodus_chain_config_db_migrate(fx->w) != 0) return -1;
    if (nodus_witness_db_migrate_v2s9(fx->w) != 0) return -1;

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
        d.delegated_at_block = 1;
        if (nodus_delegation_insert(fx->w, &d) != 0) return -1;
    }
    {
        char sql[128];
        snprintf(sql, sizeof(sql),
                 "UPDATE validator_stats SET value = %d "
                 "WHERE key = 'active_count'", (int)n_spec);
        if (run_sql(fx->w->db, sql) != 0) return -1;
    }
    /* genesis == Σ CORE utxo + Σ self_stake + Σ delegated — the exact
     * RHS the CORE invariant sums (nodus_witness_v2_claims.c:928-944). */
    {
        uint64_t supply = UTXO_A + bonds + delegated_total;
        char sql[320];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO supply_tracking (id, genesis_supply, "
                 "total_burned, total_minted, current_supply, "
                 "last_tx_hash, last_sequence) VALUES (1, %llu, 0, 0, "
                 "%llu, zeroblob(64), 0)",
                 (unsigned long long)supply, (unsigned long long)supply);
        if (run_sql(fx->w->db, sql) != 0) return -1;
    }
    if (seed_utxo(fx, 0, UTXO_A, 0xA1) != 0) return -1;
    /* MUST run BEFORE the V2 genesis: validator_set_snapshots feeds the
     * vset leg of system_state_root, so the genesis DomainHead has to
     * commit the seeded rows (test_v2_epoch.c:451-460). */
    if (nodus_witness_vset_commit_genesis(fx->w, 1) != 0) return -1;
    return 0;
}

static int fx_stage2(fixture_t *fx) {
    uint8_t vset[64];
    mk_id(vset, 0x77);
    if (v2x_genesis_min(fx->w, vset, NULL, NULL) != 0) return -1;
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

/* Apply one zero-envelope block at the next height, optionally crediting
 * a REAL proposer. `proposer_key` < 0 means an all-zero proposer_id — the
 * O15C writer's documented no-op (nodus_witness_v2_epoch.c:444-449). */
static int fx_block_by(fixture_t *fx, int proposer_key, int *rc_out) {
    uint64_t h = fx->height + 1;
    if (h % E == 0 && seed_legacy_block(fx, h - 1) != 0) return -1;
    nodus_v2_block_t b;
    memset(&b, 0, sizeof(b));
    b.global_height = h;
    b.epoch  = nodus_v2_epoch_for_height(h);
    b.envs   = NULL;
    b.n_envs = 0;
    if (proposer_key >= 0) {
        uint8_t digest[64];
        if (qgp_sha3_512(g_pk[proposer_key], DNAC_PUBKEY_SIZE, digest) != 0)
            return -1;
        memcpy(b.proposer_id, digest, 32);
    }
    int rc = nodus_witness_v2_apply_block(fx->w, &b);
    if (rc_out) *rc_out = rc;
    if (rc == 0) fx->height = h;
    if (rc != 0)
        fprintf(stderr, "block %llu rejected (rc=%d): %s\n",
                (unsigned long long)h, rc, b.out_reason);
    return rc == 0 ? 0 : -1;
}

/* Drive to `target`; every block in [attend_from, attend_to] is PROPOSED
 * by `proposer_key`, so the real O15C attendance writer accumulates its
 * counter from a committed header field. */
static int fx_drive(fixture_t *fx, uint64_t target, int proposer_key,
                    uint64_t attend_from, uint64_t attend_to) {
    while (fx->height < target) {
        uint64_t h = fx->height + 1;
        int who = (proposer_key >= 0 && h >= attend_from && h <= attend_to)
                  ? proposer_key : -1;
        if (fx_block_by(fx, who, NULL) != 0) return -1;
    }
    return 0;
}

static int fx_drive_to(fixture_t *fx, uint64_t target) {
    return fx_drive(fx, target, -1, 0, 0);
}

/* ── readers ─────────────────────────────────────────────────────────── */

typedef struct {
    int      found;
    char     owner[129];
    uint64_t amount, block_height, created_at, unlock_block;
    int64_t  output_index, domain_id;
    int      txh_len, tok_len, tok_zero, txh_match;
} utxo_row_t;

static int utxo_get(nodus_witness_t *w, const uint8_t nul[64],
                    const uint8_t want_txh[64], utxo_row_t *r) {
    memset(r, 0, sizeof(*r));
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT owner, amount, token_id, tx_hash, output_index, "
            "block_height, created_at, unlock_block, domain_id "
            "FROM utxo_set WHERE nullifier = ?1", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, nul, 64, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *o = (const char *)sqlite3_column_text(st, 0);
        int ol = sqlite3_column_bytes(st, 0);
        if (o && ol == 128) memcpy(r->owner, o, 128);
        r->amount  = (uint64_t)sqlite3_column_int64(st, 1);
        r->tok_len = sqlite3_column_bytes(st, 2);
        if (r->tok_len == 64) {
            const uint8_t *t = sqlite3_column_blob(st, 2);
            r->tok_zero = 1;
            for (int i = 0; i < 64; i++)
                if (t[i]) { r->tok_zero = 0; break; }
        }
        r->txh_len = sqlite3_column_bytes(st, 3);
        if (r->txh_len == 64)
            r->txh_match = memcmp(sqlite3_column_blob(st, 3),
                                  want_txh, 64) == 0;
        r->output_index = sqlite3_column_int64(st, 4);
        r->block_height = (uint64_t)sqlite3_column_int64(st, 5);
        r->created_at   = (uint64_t)sqlite3_column_int64(st, 6);
        r->unlock_block = (uint64_t)sqlite3_column_int64(st, 7);
        r->domain_id    = sqlite3_column_int64(st, 8);
        r->found = 1;
    }
    sqlite3_finalize(st);
    return 0;
}

/* Locate a payout by the identity RECOMPUTED from the two exported
 * derivations — never by reading the row's own key back out. */
static int payout_get(fixture_t *fx, uint64_t epoch_start, uint8_t kind,
                      uint32_t out_idx, utxo_row_t *r) {
    uint8_t txh[64], nul[64];
    if (nodus_witness_v2_settlement_tx_hash(epoch_start, txh) != 0)
        return -1;
    if (nodus_witness_v2_settlement_nullifier(txh, kind, out_idx, nul) != 0)
        return -1;
    return utxo_get(fx->w, nul, txh, r);
}

static int fp_of(int key, char out[129]) {
    uint8_t raw[QGP_FP_RAW_BYTES];
    if (qgp_sha3_512(g_pk[key], DNAC_PUBKEY_SIZE, raw) != 0) return -1;
    qgp_fp_raw_to_hex(raw, out);
    return 0;
}

static uint64_t signed_count(fixture_t *fx, int key) {
    dnac_validator_record_t v;
    if (nodus_validator_get(fx->w, g_pk[key], &v) != 0) return UINT64_MAX;
    return v.signed_blocks_this_epoch;
}

/* Total emission accruing into the epoch that starts at `epoch_start`,
 * summed INDEPENDENTLY of the engine over the heights that epoch owns:
 * max(epoch_start, 1) .. epoch_start + E - 1. Height 0 is genesis and is
 * never minted — apply_block refuses height 0 outright. */
static uint64_t pool_expected(uint64_t epoch_start) {
    uint64_t sum = 0;
    uint64_t from = (epoch_start == 0) ? 1 : epoch_start;
    for (uint64_t h = from; h < epoch_start + E; h++)
        sum += nodus_emission_per_block(h);
    return sum;
}

/* §6 — the six-term CORE conservation equation, recomputed from the
 * tables rather than by asking the gate. The gate is checked SEPARATELY
 * on the same states, so a mutation that breaks the gate helper itself
 * still shows up as one of the two disagreeing. */
typedef struct {
    uint64_t genesis, minted, burned;
    uint64_t utxo, bonds, delegated, pool;
} supply_terms_t;

static int supply_terms(nodus_witness_t *w, supply_terms_t *t) {
    memset(t, 0, sizeof(*t));
    nodus_witness_supply_t s;
    memset(&s, 0, sizeof(s));
    if (nodus_witness_supply_get(w, &s) != 0) return -1;
    t->genesis   = s.genesis_supply;
    t->minted    = s.total_minted;
    t->burned    = s.total_burned;
    t->utxo      = q1(w, "SELECT COALESCE(SUM(amount),0) FROM utxo_set");
    t->bonds     = q1(w, "SELECT COALESCE(SUM(self_stake),0) "
                         "FROM validators");
    t->delegated = q1(w, "SELECT COALESCE(SUM(total_delegated),0) "
                         "FROM validators");
    t->pool      = q1(w, "SELECT COALESCE(SUM(epoch_pool_accum),0) "
                         "FROM epoch_state");
    return 0;
}

static int supply_balances(const supply_terms_t *t) {
    return t->genesis + t->minted - t->burned ==
           t->utxo + t->bonds + t->delegated + t->pool;
}

/* ══════════════════════════════════════════════════════════════════════
 * §1 EMISSION GATE
 * ════════════════════════════════════════════════════════════════════ */

static const vspec_t SPEC3[3] = {
    { 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 0 },
    { 1, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 0 },
    { 2, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 0 },
};

static int t_emission_accrues(void) {
    fixture_t fx;
    CHECK(fx_stage1(&fx, "em_on", SPEC3, 3, NULL, 0) == 0, "stage1");
    CHECK(fx_stage2(&fx) == 0, "stage2");

    /* Genesis mints nothing: it does not go through apply_block. */
    CHECK(q1(fx.w, "SELECT total_minted FROM supply_tracking") == 0,
          "genesis must not mint");
    OK();

    CHECK(fx_drive_to(&fx, 3) == 0, "drive 3");

    uint64_t want = nodus_emission_per_block(1) +
                    nodus_emission_per_block(2) +
                    nodus_emission_per_block(3);
    CHECK(want > 0, "FIXTURE GUARD: the schedule must pay at heights 1-3");

    /* KILLED BY: deleting the supply_add_minted call, or gating emission
     * on anything other than the height. */
    CHECK(q1(fx.w, "SELECT total_minted FROM supply_tracking") == want,
          "total_minted equals the summed schedule");
    OK();

    /* KILLED BY: deleting the epoch_add_pool call — and NOT killed by
     * deleting only the mint, which the assertion above owns. The two
     * halves are asserted separately on purpose: a port that moves one
     * without the other breaks the conservation equation, and a single
     * assertion covering both could not say which half was lost. */
    CHECK(q1f(fx.w, "SELECT epoch_pool_accum FROM epoch_state "
                    "WHERE epoch_start_height = %llu", 0) == want,
          "the pool equals the same summed schedule");
    OK();

    CHECK(q1(fx.w, "SELECT current_supply FROM supply_tracking") ==
          UTXO_A + 3 * BOND_BASE + want,
          "current_supply tracks the mint");
    OK();

    supply_terms_t t;
    CHECK(supply_terms(fx.w, &t) == 0, "terms");
    CHECK(supply_balances(&t), "the equation holds across three mints");
    OK();
    CHECK(nodus_witness_v2_supply_check(fx.w) == 0, "gate GREEN");
    OK();

    fx_close(&fx);
    return 0;
}

static int t_emission_disabled(void) {
    fixture_t fx;
    CHECK(fx_stage1(&fx, "em_off", SPEC3, 3, NULL, 0) == 0, "stage1");
    /* 0 = inflation OFF (dnac.h:332). */
    CHECK(seed_inflation_start(&fx, 0) == 0, "seed override 0");
    CHECK(fx_stage2(&fx) == 0, "stage2");
    CHECK(fx_drive_to(&fx, 3) == 0, "drive 3");

    /* KILLED BY: dropping the `inflation_start != 0` conjunct — without
     * it `height >= 0` is true everywhere and the chain mints despite an
     * explicit OFF. */
    CHECK(q1(fx.w, "SELECT total_minted FROM supply_tracking") == 0,
          "an explicit 0 override mints nothing");
    OK();
    CHECK(q1(fx.w, "SELECT COUNT(*) FROM epoch_state") == 0,
          "and creates no epoch row at all");
    OK();
    CHECK(nodus_witness_v2_supply_check(fx.w) == 0,
          "a mint-free chain still conserves");
    OK();
    fx_close(&fx);
    return 0;
}

static int t_emission_start_block(void) {
    fixture_t fx;
    CHECK(fx_stage1(&fx, "em_k", SPEC3, 3, NULL, 0) == 0, "stage1");
    CHECK(seed_inflation_start(&fx, 3) == 0, "seed override 3");
    CHECK(fx_stage2(&fx) == 0, "stage2");

    CHECK(fx_drive_to(&fx, 2) == 0, "drive 2");
    /* KILLED BY: ignoring the start block, or comparing against the
     * epoch instead of the height. */
    CHECK(q1(fx.w, "SELECT total_minted FROM supply_tracking") == 0,
          "no mint below the start block");
    OK();

    CHECK(fx_drive_to(&fx, 3) == 0, "drive 3");
    /* KILLED BY: turning `>=` into `>`. Together with the assertion
     * above this pins the boundary from BOTH sides — each mutant kills
     * exactly one, so neither is redundant. */
    CHECK(q1(fx.w, "SELECT total_minted FROM supply_tracking") ==
          nodus_emission_per_block(3),
          "the start block itself mints");
    OK();
    fx_close(&fx);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §2 EPOCH-START SNAPSHOT
 * ════════════════════════════════════════════════════════════════════ */

static int t_epoch_snapshot_written(void) {
    fixture_t fx;
    CHECK(fx_stage1(&fx, "snap", SPEC3, 3, NULL, 0) == 0, "stage1");
    CHECK(fx_stage2(&fx) == 0, "stage2");
    CHECK(fx_drive_to(&fx, 1) == 0, "drive 1");

    nodus_epoch_state_t es;
    memset(&es, 0, sizeof(es));
    CHECK(nodus_witness_epoch_get(fx.w, 0, &es) == 0, "epoch row exists");
    OK();

    /* KILLED BY: deleting the nodus_witness_epoch_snapshot_apply call.
     * The row would still exist — epoch_insert seeds it — but with an
     * all-zero hash and a NULL blob, so this is NOT already covered by
     * the pool assertion in §1. */
    CHECK(es.snapshot_blob != NULL && es.snapshot_blob_len >= 6,
          "the snapshot blob is present and at least canonical-empty");
    OK();

    /* KILLED BY: passing the wrong epoch key to snapshot_apply — a
     * foreign epoch's committee decodes to a different count. */
    uint16_t cc = (uint16_t)(((uint16_t)es.snapshot_blob[0] << 8) |
                             es.snapshot_blob[1]);
    CHECK(cc == 3, "the snapshot carries this epoch's three seats");
    OK();

    /* Every seat is a seeded validator carrying its REAL bond, at the
     * documented stride (nodus_witness_epoch.h:99-107). KILLED BY: a
     * snapshot built from a different table, or one that zero-fills the
     * stake it could not read. */
    const size_t VROW = DNAC_PUBKEY_SIZE + 8 + 8 + 2 + 1;
    for (uint16_t i = 0; i < cc; i++) {
        const uint8_t *row = es.snapshot_blob + 2 + (size_t)i * VROW;
        int match = 0;
        for (int k = 0; k < 3; k++)
            if (memcmp(row, g_pk[SPEC3[k].key], DNAC_PUBKEY_SIZE) == 0)
                match = 1;
        CHECK(match, "each snapshot seat is a seeded validator");
        uint64_t stake = 0;
        for (int b = 0; b < 8; b++)
            stake = (stake << 8) | row[DNAC_PUBKEY_SIZE + b];
        CHECK(stake == BOND_BASE, "the seat carries its real self_stake");
    }
    OK();

    /* KILLED BY: storing the hash of anything other than the blob. */
    uint8_t h[64];
    CHECK(qgp_sha3_512(es.snapshot_blob, es.snapshot_blob_len, h) == 0,
          "hash the blob");
    CHECK(memcmp(h, es.snapshot_hash, 64) == 0,
          "snapshot_hash is SHA3-512 over the stored blob");
    OK();

    nodus_witness_epoch_free(&es);
    fx_close(&fx);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §3 SETTLEMENT — flat split + burn leg 1 (outer dust)
 * ════════════════════════════════════════════════════════════════════ */

/* ══════════════════════════════════════════════════════════════════
 * FAULT-POINT ROLLBACK — review R2-F5
 *
 * Faz 2 declared three fault points (50/51/52) and wired them, and
 * NOTHING drove them. Every other stage id in this tree carries a
 * whole-DB-digest rollback proof; these shipped with a prose obligation
 * and no test. R2 found the gap by grepping for `fail_at` and finding
 * only the declarations.
 *
 * The obligation, from nodus_witness_v2_apply.h:
 *   50 — fires with every settlement payout UTXO WRITTEN and nothing
 *        burned or retired. An interrupt must leave NO payout row AND
 *        no supply movement.
 *   51 — fires with the burn recorded and the settled epoch row retired,
 *        one step before Rule N. The second rollback window.
 *   52 — brackets the per-block mint: total_minted and epoch_pool_accum
 *        move together or not at all. That is the conservation
 *        equation's own precondition.
 *
 * Apply a block with the fault injected, then prove the whole-database
 * digest is BYTE-IDENTICAL — not that a few columns look unchanged.
 * Then prove a clean retry commits, so the rollback did not poison the
 * chain.
 * ══════════════════════════════════════════════════════════════════ */

/* Apply the next block with `pt` injected. Returns 0 iff the engine
 * reported a rollback class AND the whole-DB digest did not move. */
static int fx_block_inject(fixture_t *fx, nodus_v2_apply_fail_t pt,
                           int *rc_out) {
    uint64_t h = fx->height + 1;
    if (h % E == 0 && seed_legacy_block(fx, h - 1) != 0) return -1;

    uint8_t d0[64], d1[64];
    if (v2x_db_digest(fx->w, d0) != 0) return -1;

    nodus_v2_block_t b;
    memset(&b, 0, sizeof(b));
    b.global_height = h;
    b.epoch   = nodus_v2_epoch_for_height(h);
    b.envs    = NULL;
    b.n_envs  = 0;
    b.fail_at = pt;
    {
        uint8_t digest[64];
        if (qgp_sha3_512(g_pk[0], DNAC_PUBKEY_SIZE, digest) != 0) return -1;
        memcpy(b.proposer_id, digest, 32);
    }
    int rc = nodus_witness_v2_apply_block(fx->w, &b);
    if (rc_out) *rc_out = rc;
    /* -1 verdict or -2 node fault; anything else means the fault point
     * did not fire and the test proves nothing. */
    if (rc != -1 && rc != -2) return -1;

    if (v2x_db_digest(fx->w, d1) != 0) return -1;
    return memcmp(d0, d1, 64) == 0 ? 0 : -1;
}

static int t_fault_emission(void) {
    fixture_t fx;
    CHECK(fx_stage1(&fx, "f52", SPEC3, 3, NULL, 0) == 0, "stage1");
    CHECK(fx_stage2(&fx) == 0, "stage2");
    CHECK(fx_drive_to(&fx, 2) == 0, "drive 2");

    const uint64_t minted_pre = q1(fx.w,
        "SELECT total_minted FROM supply_tracking");
    CHECK(minted_pre > 0, "FIXTURE GUARD: the chain must already mint");
    OK();

    int rc = 0;
    CHECK(fx_block_inject(&fx, V2AP_FAIL_AFTER_EMISSION, &rc) == 0,
          "F52: the mint rolled back byte-identically");
    OK();

    /* The half-applied state F52 exists to forbid: minted moved without
     * the pool, or the reverse. Both are covered by the digest above;
     * these two name the columns so a failure says WHICH half leaked. */
    CHECK(q1(fx.w, "SELECT total_minted FROM supply_tracking")
              == minted_pre, "F52 leaked a mint");
    OK();

    /* A clean retry at the same height must still commit. */
    CHECK(fx_block_by(&fx, 0, NULL) == 0, "clean retry after F52");
    CHECK(q1(fx.w, "SELECT total_minted FROM supply_tracking")
              > minted_pre, "the retry actually minted");
    OK();
    CHECK(nodus_witness_v2_supply_check(fx.w) == 0, "gate GREEN after retry");
    OK();

    fx_close(&fx);
    return 0;
}

static int t_fault_settlement(void) {
    /* Both settlement fault points need a boundary with a real pool, so
     * this drives one fixture to E-1 and injects at height E twice. */
    for (int leg = 0; leg < 2; leg++) {
        const nodus_v2_apply_fail_t pt =
            leg == 0 ? V2AP_FAIL_AFTER_SETTLE_EMITTED
                     : V2AP_FAIL_AFTER_SETTLE_APPLIED;
        const char *tag = leg == 0 ? "f50" : "f51";

        fixture_t fx;
        CHECK(fx_stage1(&fx, tag, SPEC3, 3, NULL, 0) == 0, "stage1");
        CHECK(fx_stage2(&fx) == 0, "stage2");
        CHECK(fx_drive_to(&fx, E - 1) == 0, "drive to E-1");

        const uint64_t pool = pool_expected(0);
        CHECK(q1f(fx.w, "SELECT epoch_pool_accum FROM epoch_state "
                        "WHERE epoch_start_height = %llu", 0) == pool,
              "FIXTURE GUARD: a pool must exist to settle");
        OK();
        /* Baseline, not an assumed zero: the fixture may legitimately
         * already hold rows. What matters is that the rollback leaves
         * the count exactly where it was. */
        const uint64_t utxo_pre =
            q1(fx.w, "SELECT COUNT(*) FROM utxo_set");

        int rc = 0;
        CHECK(fx_block_inject(&fx, pt, &rc) == 0,
              leg == 0 ? "F50: payouts written, rolled back byte-identically"
                       : "F51: burn+retire, rolled back byte-identically");
        OK();

        /* Name the two halves the digest already covers, so a failure
         * reports WHICH survived rather than only that something did. */
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM utxo_set") == utxo_pre,
              "a payout UTXO survived the rollback");
        OK();
        CHECK(q1(fx.w, "SELECT total_burned FROM supply_tracking") == 0,
              "a burn survived the rollback");
        OK();
        CHECK(q1f(fx.w, "SELECT COUNT(*) FROM epoch_state "
                        "WHERE epoch_start_height = %llu", 0) == 1,
              "the settled epoch row was retired despite the rollback");
        OK();

        /* Clean retry: the same boundary must settle for real. */
        CHECK(fx_block_by(&fx, 0, NULL) == 0, "clean retry at the boundary");
        CHECK(q1(fx.w, "SELECT COUNT(*) FROM utxo_set") > utxo_pre,
              "the retry paid nobody");
        OK();
        CHECK(nodus_witness_v2_supply_check(fx.w) == 0,
              "gate GREEN after the retried boundary");
        OK();

        fx_close(&fx);
    }
    return 0;
}

static int t_settlement_flat(void) {
    fixture_t fx;
    CHECK(fx_stage1(&fx, "flat", SPEC3, 3, NULL, 0) == 0, "stage1");
    CHECK(fx_stage2(&fx) == 0, "stage2");

    CHECK(fx_drive_to(&fx, E - 1) == 0, "drive to E-1");
    const uint64_t pool = pool_expected(0);
    CHECK(q1f(fx.w, "SELECT epoch_pool_accum FROM epoch_state "
                    "WHERE epoch_start_height = %llu", 0) == pool,
          "the whole epoch accrued into epoch 0");
    OK();
    /* KILLED BY: firing settlement on a non-boundary height. */
    CHECK(q1(fx.w, "SELECT total_burned FROM supply_tracking") == 0,
          "nothing burns before the boundary");
    OK();

    supply_terms_t pre;
    CHECK(supply_terms(fx.w, &pre) == 0, "pre terms");
    CHECK(supply_balances(&pre), "the equation holds before settlement");
    OK();

    CHECK(fx_drive_to(&fx, E) == 0, "drive the boundary");

    const uint64_t per_slot   = pool / 3;
    const uint64_t outer_dust = pool - per_slot * 3;
    CHECK(per_slot > 0, "FIXTURE GUARD: the pool must be splittable");

    char want_fp[3][129];
    for (int k = 0; k < 3; k++)
        CHECK(fp_of(SPEC3[k].key, want_fp[k]) == 0, "fp");

    uint64_t paid_total = 0;
    int owner_hits[3] = { 0, 0, 0 };
    for (uint32_t i = 0; i < 3; i++) {
        utxo_row_t r;
        CHECK(payout_get(&fx, 0, NODUS_V2_SETTLE_KIND_VALIDATOR,
                         NODUS_V2_SETTLE_OUT_IDX_BASE + i, &r) == 0,
              "read payout");
        /* KILLED BY: any change to the tx_hash preimage, the nullifier
         * preimage, the kind byte or the 400 index base — the row would
         * live under a different key and this lookup would miss. */
        CHECK(r.found, "the payout row exists at the derived identity");
        /* KILLED BY: a wrong per_slot — dividing by the CURRENT
         * validator count instead of the snapshot's committee_count is
         * the realistic version of that mutation. */
        CHECK(r.amount == per_slot, "each seat is paid exactly per_slot");
        CHECK(r.txh_len == 64 && r.txh_match,
              "the row's provenance is the settlement tx_hash");
        /* KILLED BY: copying V1's INSERT verbatim — it binds no
         * domain_id at all, and the V2 schema has no default for it. */
        CHECK(r.domain_id == (int64_t)DNA_DOMAIN_CORE, "CORE-owned row");
        /* KILLED BY: carrying V1's `time(NULL)` into this lane. */
        CHECK(r.created_at == 0, "created_at is pinned, not a wall clock");
        CHECK(r.unlock_block == 0, "settlement rewards unlock immediately");
        CHECK(r.block_height == 0,
              "block_height is the settled epoch key — V1's own choice");
        CHECK(r.output_index == (int64_t)(NODUS_V2_SETTLE_OUT_IDX_BASE + i),
              "the row records its own output index");
        CHECK(r.tok_len == 64 && r.tok_zero, "native token id = 64 zeros");
        for (int k = 0; k < 3; k++)
            if (memcmp(r.owner, want_fp[k], 128) == 0) owner_hits[k]++;
        paid_total += r.amount;
    }
    OK();

    /* KILLED BY: paying one owner three times — e.g. hoisting the
     * committee pubkey out of the loop, which no amount assertion above
     * would catch because every amount would still be per_slot. */
    for (int k = 0; k < 3; k++)
        CHECK(owner_hits[k] == 1,
              "each seeded validator is paid exactly once");
    OK();

    /* BURN LEG 1 of 3. KILLED BY: dropping
     * `total_burned_here = pool - per_slot * committee_count`, which
     * leaves total_burned at 0 whenever pool % 3 != 0. */
    CHECK(q1(fx.w, "SELECT total_burned FROM supply_tracking") ==
          outer_dust, "the outer dust is burned, exactly");
    OK();
    /* THE LEG-COMPLETENESS IDENTITY: every raw unit of the pool is
     * either paid or burned. KILLED BY dropping ANY burn leg — the sum
     * falls short of `pool` by exactly the dropped amount. */
    CHECK(paid_total + outer_dust == pool,
          "paid + burned accounts for the WHOLE pool");
    OK();

    /* KILLED BY: removing the epoch_delete — the settled pool would stay
     * in the equation's RHS forever and the next gate would fail. */
    CHECK(q1f(fx.w, "SELECT COUNT(*) FROM epoch_state "
                    "WHERE epoch_start_height = %llu", 0) == 0,
          "the settled epoch row is retired");
    OK();
    CHECK(q1f(fx.w, "SELECT epoch_pool_accum FROM epoch_state "
                    "WHERE epoch_start_height = %llu", E) ==
          nodus_emission_per_block(E),
          "the boundary block's own mint seeds the NEW epoch");
    OK();

    supply_terms_t post;
    CHECK(supply_terms(fx.w, &post) == 0, "post terms");
    CHECK(supply_balances(&post), "the equation holds after settlement");
    OK();
    /* KILLED BY: burning an amount other than the dust — the LHS would
     * move by a different delta than the RHS did. */
    CHECK(post.burned - pre.burned == outer_dust,
          "the burn delta across the boundary is the dust and nothing else");
    OK();
    CHECK(nodus_witness_v2_supply_check(fx.w) == 0, "gate GREEN");
    OK();

    fx_close(&fx);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §4 SETTLEMENT — delegation split + burn leg 3 (inner dust)
 *
 * Also covers the zero-share skip: a delegation too small to earn one
 * raw unit must write NO row at all.
 * ════════════════════════════════════════════════════════════════════ */

#define COMM_BPS 1500

/* THREE delegations, and the shape is chosen so the inner dust CANNOT be
 * zero — otherwise a dropped burn leg 3 would be unobservable and the
 * assertions covering it would be vacuous:
 *
 *   - the exact shares sum to delegator_net (an integer), so the three
 *     FRACTIONAL parts the floors discard sum to an integer in {0,1,2},
 *     and inner_dust is exactly that integer;
 *   - it can only be 0 if all three fractions are 0, which would need
 *     total_delegated to divide delegator_net * 1 — impossible, because
 *     the first delegation is ONE raw unit and 0 < delegator_net <
 *     total_delegated at these magnitudes.
 *
 * So inner_dust >= 1 by construction. The 1-unit delegation also earns a
 * share that FLOORS TO ZERO, which pins V1's `if (share > 0)` skip
 * (bft.c:3308): a row must NOT be written for it. The other two are a
 * clean 60/40 split, so the weighting formula is pinned by a value that
 * is not degenerate. */
static const dspec_t DELS[3] = {
    { 7, 0, 1ULL },
    { 8, 0, 3000000ULL * 100000000ULL },
    { 9, 0, 2000000ULL * 100000000ULL },
};

static const vspec_t SPECD[3] = {
    { 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE, COMM_BPS },
    { 1, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 0 },
    { 2, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 0 },
};

static int t_settlement_delegated(void) {
    fixture_t fx;
    CHECK(fx_stage1(&fx, "deleg", SPECD, 3, DELS, 3) == 0, "stage1");
    CHECK(fx_stage2(&fx) == 0, "stage2");
    CHECK(fx_drive_to(&fx, E) == 0, "drive the boundary");

    const uint64_t pool     = pool_expected(0);
    const uint64_t per_slot = pool / 3;
    const uint64_t outer    = pool - per_slot * 3;

    /* The V1 formula (bft.c:3277-3326), recomputed INDEPENDENTLY here
     * with the compiler's own 128-bit type rather than by calling the
     * implementation's qgp_u128 helpers — an independent computation,
     * not a mirror of the code under test. */
    const uint64_t deleg_total =
        DELS[0].amount + DELS[1].amount + DELS[2].amount;
    const uint64_t total_stake = BOND_BASE + deleg_total;
    const uint64_t validator_base =
        (uint64_t)(((__uint128_t)per_slot * BOND_BASE) / total_stake);
    const uint64_t delegator_gross = per_slot - validator_base;
    const uint64_t commission =
        (uint64_t)(((__uint128_t)delegator_gross * COMM_BPS) / 10000u);
    const uint64_t validator_total = validator_base + commission;
    const uint64_t delegator_net   = delegator_gross - commission;
    uint64_t share[3], share_sum = 0;
    for (int i = 0; i < 3; i++) {
        share[i] = (uint64_t)(((__uint128_t)delegator_net *
                               DELS[i].amount) / deleg_total);
        share_sum += share[i];
    }
    const uint64_t inner_dust = delegator_net - share_sum;

    CHECK(commission > 0,
          "FIXTURE GUARD: the commission must not round to zero");
    CHECK(validator_base > 0 && delegator_net > 0,
          "FIXTURE GUARD: the split must be real on both sides");
    CHECK(share[0] == 0,
          "FIXTURE GUARD: the 1-unit delegation must floor to a zero "
          "share, so V1's `share > 0` skip is exercised");
    CHECK(share[1] > 0 && share[2] > 0 && share[1] != share[2],
          "FIXTURE GUARD: the other two shares must be real and unequal, "
          "so the weighting is not degenerate");
    /* Without this the inner-dust assertions below would be vacuous. It
     * cannot fire — see the DELS comment — but a future edit to the
     * amounts would trip it rather than silently gutting the test. */
    CHECK(inner_dust > 0,
          "FIXTURE GUARD: the delegation amounts must leave a real "
          "remainder");
    OK();

    char fp_val[129], fp_d[3][129];
    CHECK(fp_of(0, fp_val) == 0, "validator fp");
    for (int i = 0; i < 3; i++)
        CHECK(fp_of(DELS[i].delegator_key, fp_d[i]) == 0, "delegator fp");

    /* The committee is walked in the SNAPSHOT's order, which the test
     * deliberately does not assume: it scans the whole emitted index
     * range and classifies each row by owner and amount. */
    int seen_d[3] = { 0, 0, 0 };
    int seen_valtotal = 0, seen_flat = 0;
    uint64_t paid_total = 0;
    for (uint32_t i = 0; i < 10; i++) {
        for (int kk = 0; kk < 2; kk++) {
            uint8_t kind = (kk == 0) ? NODUS_V2_SETTLE_KIND_VALIDATOR
                                     : NODUS_V2_SETTLE_KIND_DELEGATOR;
            utxo_row_t r;
            CHECK(payout_get(&fx, 0, kind,
                             NODUS_V2_SETTLE_OUT_IDX_BASE + i, &r) == 0,
                  "read");
            if (!r.found) continue;
            paid_total += r.amount;
            if (kind == NODUS_V2_SETTLE_KIND_DELEGATOR) {
                /* KILLED BY: paying the delegator the GROSS (dropping
                 * the commission subtraction), weighting the share by
                 * anything but its own amount, or sending it to the
                 * validator's fingerprint. */
                int which = -1;
                for (int d = 0; d < 3; d++)
                    if (memcmp(r.owner, fp_d[d], 128) == 0) which = d;
                CHECK(which >= 0,
                      "a delegator payout goes to a DELEGATOR");
                CHECK(r.amount == share[which],
                      "the share is net * this delegation / total");
                seen_d[which]++;
            } else if (memcmp(r.owner, fp_val, 128) == 0) {
                /* KILLED BY: dropping the commission from the
                 * consolidated payout, or paying a delegated validator
                 * the flat per_slot as if it had no delegations. */
                CHECK(r.amount == validator_total,
                      "the delegated validator gets base + commission");
                seen_valtotal++;
            } else {
                CHECK(r.amount == per_slot,
                      "an undelegated seat is paid the flat per_slot");
                seen_flat++;
            }
        }
    }
    /* KILLED BY: removing V1's `if (share > 0) continue` skip — a
     * zero-amount row would appear for delegator 0. */
    CHECK(seen_d[0] == 0, "the zero-share delegation writes NO row");
    OK();
    CHECK(seen_d[1] == 1 && seen_d[2] == 1,
          "exactly one payout per paying delegator");
    OK();
    CHECK(seen_valtotal == 1,
          "exactly one consolidated base+commission payout");
    OK();
    CHECK(seen_flat == 2, "the two undelegated seats are paid flat");
    OK();

    /* BURN LEGS 1 and 3, through the ONE counter that carries them.
     * KILLED BY: dropping either leg — with inner_dust > 0 guaranteed
     * above, dropping leg 3 alone changes this value. */
    CHECK(q1(fx.w, "SELECT total_burned FROM supply_tracking") ==
          outer + inner_dust, "burned == outer dust + inner dust");
    OK();
    /* THE LEG-COMPLETENESS IDENTITY. */
    CHECK(paid_total + outer + inner_dust == pool,
          "paid + every burn leg == the whole pool");
    OK();

    supply_terms_t t;
    CHECK(supply_terms(fx.w, &t) == 0, "terms");
    CHECK(supply_balances(&t),
          "the equation holds with delegations in play");
    OK();
    CHECK(nodus_witness_v2_supply_check(fx.w) == 0, "gate GREEN");
    OK();

    fx_close(&fx);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §5 OFFLINE SHARE — burn leg 2, and the ordering proof
 * ════════════════════════════════════════════════════════════════════ */

static int t_settlement_offline(void) {
    fixture_t fx;
    CHECK(fx_stage1(&fx, "offline", SPEC3, 3, NULL, 0) == 0, "stage1");
    CHECK(fx_stage2(&fx) == 0, "stage2");

    /* Epoch 0 settles under the genesis carve-out — drive past it and
     * record where the burn counter stood, so the epoch-1 delta is
     * isolated from it. */
    CHECK(fx_drive_to(&fx, E) == 0, "drive to the first boundary");
    const uint64_t burned_after_epoch0 =
        q1(fx.w, "SELECT total_burned FROM supply_tracking");
    CHECK(burned_after_epoch0 == pool_expected(0) - (pool_expected(0) / 3) * 3,
          "epoch 0 burned only its outer dust — the carve-out paid "
          "everyone despite a zero attendance counter");
    OK();

    /* Epoch 1 (heights E .. 2E-1). Validator 0 proposes exactly enough
     * blocks to reach the liveness bar; 1 and 2 propose none. The counter
     * is written ONLY by the real O15C writer from the committed header
     * proposer — nothing here touches `validators` directly, so this
     * test cannot pass by seeding an outcome the engine would not
     * produce.
     *
     * Bar (bft.c:3239-3245), rearranged exactly as the source does:
     *   signed * committee_count * 10000 >= EPOCH_LENGTH * BPS. */
    const uint64_t required =
        (E * (uint64_t)DNAC_LIVENESS_THRESHOLD_BPS + (3ULL * 10000ULL) - 1)
        / (3ULL * 10000ULL);
    CHECK(required > 0 && required < E - 1,
          "FIXTURE GUARD: the bar must be reachable inside one epoch");
    CHECK(required * 3ULL * 10000ULL >=
          E * (uint64_t)DNAC_LIVENESS_THRESHOLD_BPS,
          "FIXTURE GUARD: `required` really does clear the bar");
    OK();

    CHECK(fx_drive(&fx, E + required, 0, E + 1, E + required) == 0,
          "propose the attending blocks");
    CHECK(signed_count(&fx, 0) == required,
          "the REAL attendance writer accumulated the counter");
    OK();
    CHECK(signed_count(&fx, 1) == 0 && signed_count(&fx, 2) == 0,
          "and credited nobody else");
    OK();

    CHECK(fx_drive_to(&fx, 2 * E) == 0, "drive the second boundary");

    const uint64_t pool     = pool_expected(E);
    const uint64_t per_slot = pool / 3;
    const uint64_t outer    = pool - per_slot * 3;

    char fp0[129];
    CHECK(fp_of(0, fp0) == 0, "fp");
    int found = 0;
    uint64_t paid = 0;
    for (uint32_t i = 0; i < 6; i++) {
        for (int kk = 0; kk < 2; kk++) {
            uint8_t kind = (kk == 0) ? NODUS_V2_SETTLE_KIND_VALIDATOR
                                     : NODUS_V2_SETTLE_KIND_DELEGATOR;
            utxo_row_t r;
            CHECK(payout_get(&fx, E, kind,
                             NODUS_V2_SETTLE_OUT_IDX_BASE + i, &r) == 0,
                  "read");
            if (!r.found) continue;
            /* KILLED BY: inverting the liveness comparison, which would
             * pay the two absentees and starve the attendee.
             *
             * ALSO KILLED BY: moving settlement AFTER Rule N. Rule N's
             * step (d) zeroes signed_blocks_this_epoch, so the gate
             * would read 0 for EVERY member, `found` would be 0, and
             * this assertion fails. That is the ordering proof — there
             * is no other test in the tree that would notice. */
            CHECK(memcmp(r.owner, fp0, 128) == 0,
                  "only the validator that attended is paid");
            CHECK(r.amount == per_slot, "and it is paid its full slot");
            paid += r.amount;
            found++;
        }
    }
    /* KILLED BY: treating every member as present unconditionally (the
     * carve-out condition widened past epoch 0), which makes found 3. */
    CHECK(found == 1, "the two absent members receive nothing");
    OK();

    /* BURN LEG 2 of 3 — two whole slots, plus this epoch's outer dust.
     *
     * COMPOUND MUTANT, named because a single one survives nothing here:
     * the offline branch both (a) adds per_slot to the burn and (b)
     * `continue`s past the payout. Deleting only (a) leaves this
     * assertion short by 2 * per_slot; deleting only (b) makes `found`
     * 3 and kills the assertion above; deleting the WHOLE branch — the
     * realistic "leg dropped" edit — kills both. No redundant guard
     * exists here for a mutant to hide behind. */
    const uint64_t burned_epoch1 =
        q1(fx.w, "SELECT total_burned FROM supply_tracking") -
        burned_after_epoch0;
    CHECK(burned_epoch1 == outer + 2 * per_slot,
          "epoch 1 burned its dust plus the two absent slots");
    OK();

    /* THE LEG-COMPLETENESS IDENTITY, again. */
    CHECK(paid + burned_epoch1 == pool,
          "paid + all burn legs == the whole epoch-1 pool");
    OK();

    supply_terms_t t;
    CHECK(supply_terms(fx.w, &t) == 0, "terms");
    CHECK(supply_balances(&t), "the equation survives an offline burn");
    OK();
    CHECK(nodus_witness_v2_supply_check(fx.w) == 0, "gate GREEN");
    OK();

    fx_close(&fx);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §7 DETERMINISM TWIN
 * ════════════════════════════════════════════════════════════════════ */

static const vspec_t SPEC3_REV[3] = {
    { 2, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 0 },
    { 1, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 0 },
    { 0, BOND_BASE, DNAC_VALIDATOR_ACTIVE, 0 },
};

static int t_determinism_twin(void) {
    fixture_t a, b;
    CHECK(fx_stage1(&a, "twin_a", SPEC3, 3, NULL, 0) == 0, "a stage1");
    CHECK(fx_stage2(&a) == 0, "a stage2");
    CHECK(fx_stage1(&b, "twin_b", SPEC3_REV, 3, NULL, 0) == 0, "b stage1");
    CHECK(fx_stage2(&b) == 0, "b stage2");

    /* A full emission + settlement cycle on both. */
    CHECK(fx_drive_to(&a, E) == 0, "a drive");
    CHECK(fx_drive_to(&b, E) == 0, "b drive");

    uint8_t sys_a[64], core_a[64], sys_b[64], core_b[64];
    CHECK(nodus_witness_system_root_v2(a.w, sys_a) == 0, "a sys");
    CHECK(nodus_witness_core_root_v2(a.w, core_a) == 0, "a core");
    CHECK(nodus_witness_system_root_v2(b.w, sys_b) == 0, "b sys");
    CHECK(nodus_witness_core_root_v2(b.w, core_b) == 0, "b core");

    /* Not vacuous: prove the compared state actually contains a settled
     * cycle before comparing it. */
    CHECK(q1(a.w, "SELECT total_minted FROM supply_tracking") > 0,
          "the twins actually minted");
    CHECK(q1(a.w, "SELECT COUNT(*) FROM utxo_set") == 4,
          "the seeded UTXO plus three settlement payouts");
    OK();

    /* KILLED BY: any unordered iteration reaching a payout identity or
     * an amount. The two fixtures inserted their validators in OPPOSITE
     * order, so a settlement that depended on insertion order — rather
     * than on the snapshot's own committed order — would put different
     * owners at the same output indices and produce a different CORE
     * root. */
    CHECK(memcmp(core_a, core_b, 64) == 0,
          "two independent fixtures agree on the CORE root");
    OK();
    CHECK(memcmp(sys_a, sys_b, 64) == 0, "and on the SYSTEM root");
    OK();

    fx_close(&a);
    fx_close(&b);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════ */

int main(void) {
    keys_init();

    struct { const char *name; int (*fn)(void); } tests[] = {
        { "emission accrues into minted AND pool", t_emission_accrues },
        { "an explicit 0 override disables emission", t_emission_disabled },
        { "INFLATION_START_BLOCK is inclusive", t_emission_start_block },
        { "the epoch-start snapshot is written", t_epoch_snapshot_written },
        { "settlement: flat split + outer dust burn", t_settlement_flat },
        { "settlement: delegation split + inner dust",
          t_settlement_delegated },
        { "settlement: offline share burn + ordering",
          t_settlement_offline },
        { "determinism twin", t_determinism_twin },
        /* review R2-F5 — the three fault points shipped undriven */
        { "F52: the per-block mint rolls back whole", t_fault_emission },
        { "F50/F51: settlement rolls back whole", t_fault_settlement },
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
