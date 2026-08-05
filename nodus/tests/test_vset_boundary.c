/**
 * Nodus — Ledger V2 S3 wave 2: epoch-boundary validator-set lifecycle.
 *
 * Exercises the three ACTIVE entry points added to
 * nodus_witness_vset.{h,c} and the dynamic committee sizing they depend
 * on:
 *
 *   1. nodus_witness_vset_commit_next   — freeze the NEXT epoch's set
 *   2. nodus_witness_vset_apply_boundary_flips — ACTIVE↔ELIGIBLE
 *   3. selection sizing from DNAC_CFG_TARGET_ACTIVE_COUNT
 *
 * WHY THE TWO FUNCTIONS ARE CALLED DIRECTLY rather than through
 * apply_epoch_boundary_transitions: that function is `static` in
 * nodus_witness_bft.c and has no internal-API prototype (unlike
 * finalize_block / commit_batch, which nodus_witness_bft_internal.h
 * exposes). The two vset entry points ARE public in
 * witness/nodus_witness_vset.h and carry the whole behaviour under test;
 * their wiring into finalize_block's order is a two-line call site
 * reviewed in the diff.
 *
 * nodus_witness_t is multi-MB — every fixture is calloc'd, never a stack
 * object.
 *
 * @file test_vset_boundary.c
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_committee.h"
#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_types.h"

#include "dnac/dnac.h"
#include "dnac/validator.h"
#include "dnac/vset_wire.h"
#include "dnac/ledger_ids.h"

#include "crypto/hash/qgp_sha3.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int g_checks = 0;
static int g_fails  = 0;

#define CHECK(cond, msg) do {                                            \
    if (!(cond)) {                                                       \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n",                   \
                __FILE__, __LINE__, (msg));                              \
        g_fails++;                                                       \
        return 1;                                                        \
    }                                                                    \
    g_checks++;                                                          \
} while (0)

/* Heights. B is the boundary under test; the committee rules need a
 * block row at B-1 (for the NEXT epoch's lookback) and at B-E-1 (for
 * THIS epoch's lookback). */
#define E_LEN     ((uint64_t)DNAC_EPOCH_LENGTH)
#define B_HEIGHT  (E_LEN * 4ULL)
#define LOOKBACK_THIS  (B_HEIGHT - E_LEN - 1ULL)
#define LOOKBACK_NEXT  (B_HEIGHT - 1ULL)

/* ── Fixture ────────────────────────────────────────────────────────── */

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
} fixture_t;

static int fx_open(fixture_t *fx, uint8_t chain_fill) {
    fx->w = calloc(1, sizeof(*fx->w));   /* multi-MB — never the stack */
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_vset_boundary_XXXXXX");
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    uint8_t chain_id[16];
    memset(chain_id, chain_fill, sizeof(chain_id));
    if (nodus_witness_create_chain_db(fx->w, chain_id) != 0) {
        rmrf(fx->dir);
        free(fx->w);
        fx->w = NULL;
        return -1;
    }
    return 0;
}

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) { sqlite3_close(fx->w->db); fx->w->db = NULL; }
    free(fx->w);
    fx->w = NULL;
    rmrf(fx->dir);
}

/* ── Seeding helpers ────────────────────────────────────────────────── */

static void init_validator(dnac_validator_record_t *v, uint8_t pub_fill,
                           uint64_t active_since, uint64_t self_stake,
                           uint64_t external_delegated, int status) {
    memset(v, 0, sizeof(*v));
    memset(v->pubkey, pub_fill, DNAC_PUBKEY_SIZE);
    v->self_stake         = self_stake;
    v->total_delegated    = external_delegated;
    v->external_delegated = external_delegated;
    v->commission_bps     = (uint16_t)(500 + pub_fill);
    v->status             = status;
    v->active_since_block = active_since;
    uint8_t fp_raw[64];
    qgp_sha3_512(v->pubkey, DNAC_PUBKEY_SIZE, fp_raw);
    static const char hex_digits[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        v->unstake_destination_fp[2 * i]     = hex_digits[fp_raw[i] >> 4];
        v->unstake_destination_fp[2 * i + 1] = hex_digits[fp_raw[i] & 0xf];
    }
    v->unstake_destination_fp[128] = '\0';
    memset(v->unstake_destination_pubkey, pub_fill, DNAC_PUBKEY_SIZE);
}

static int insert_block_row(nodus_witness_t *w, uint64_t height,
                            uint8_t seed_fill) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(w->db,
        "INSERT OR REPLACE INTO blocks "
        "(height, tx_root, tx_count, timestamp, proposer_id, prev_hash, "
        " state_root) VALUES (?, ?, 0, ?, ?, ?, ?)",
        -1, &stmt, NULL) != SQLITE_OK) return -1;
    uint8_t zeros[64] = { 0 };
    uint8_t seed[64];
    memset(seed, seed_fill, sizeof(seed));
    uint8_t proposer[NODUS_T3_WITNESS_ID_LEN];
    memset(proposer, 0xBB, sizeof(proposer));
    sqlite3_bind_int64(stmt, 1, (int64_t)height);
    sqlite3_bind_blob (stmt, 2, zeros, 64, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, 1000);
    sqlite3_bind_blob (stmt, 4, proposer, sizeof(proposer), SQLITE_STATIC);
    sqlite3_bind_blob (stmt, 5, zeros, 64, SQLITE_STATIC);
    sqlite3_bind_blob (stmt, 6, seed, 64, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int exec_sql(nodus_witness_t *w, const char *sql) {
    char *err = NULL;
    int rc = sqlite3_exec(w->db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "exec_sql failed: %s (%s)\n", err ? err : "?", sql);
        if (err) sqlite3_free(err);
        return -1;
    }
    return 0;
}

/* Read one validator's status via the CRUD layer. */
static int status_of(nodus_witness_t *w, uint8_t pub_fill) {
    uint8_t pk[DNAC_PUBKEY_SIZE];
    memset(pk, pub_fill, sizeof(pk));
    dnac_validator_record_t v;
    if (nodus_validator_get(w, pk, &v) != 0) return -1;
    return (int)v.status;
}

static uint64_t self_stake_of(nodus_witness_t *w, uint8_t pub_fill) {
    uint8_t pk[DNAC_PUBKEY_SIZE];
    memset(pk, pub_fill, sizeof(pk));
    dnac_validator_record_t v;
    if (nodus_validator_get(w, pk, &v) != 0) return UINT64_MAX;
    return v.self_stake;
}

/* Insert a chain_config_history override row directly.
 *
 * The witness caches chain_config rows in memory
 * (nodus_witness.h chain_config_cache*, warmed lazily by
 * nodus_chain_config_get_u64). A direct SQL write bypasses the apply
 * path that would normally clear the flag, so the test clears it here —
 * exactly what nodus_chain_config_apply does after its own INSERT. */
static int set_target_active(nodus_witness_t *w, uint64_t value,
                             uint64_t effective_block) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
        "INSERT OR REPLACE INTO chain_config_history "
        "(param_id, new_value, effective_block, commit_block, "
        " tx_hash, proposal_nonce, created_at_unix) VALUES (?,?,?,?,?,?,?)",
        -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "chain_config insert prepare failed: %s\n",
                sqlite3_errmsg(w->db));
        return -1;
    }
    uint8_t txh[64];
    memset(txh, (int)(effective_block & 0xff), sizeof(txh));
    sqlite3_bind_int  (st, 1, (int)DNAC_CFG_TARGET_ACTIVE_COUNT);
    sqlite3_bind_int64(st, 2, (int64_t)value);
    sqlite3_bind_int64(st, 3, (int64_t)effective_block);
    sqlite3_bind_int64(st, 4, 1);
    sqlite3_bind_blob (st, 5, txh, 64, SQLITE_STATIC);
    sqlite3_bind_int64(st, 6, (int64_t)effective_block);
    /* Constant, not time(NULL): a test fixture must not carry a wall
     * clock into a consensus-adjacent table. */
    sqlite3_bind_int64(st, 7, 0);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "chain_config insert step failed rc=%d\n", rc);
        return -1;
    }
    w->chain_config_cache_warm = false;
    return 0;
}

/* Seed `n` bonded validators, all tenured, with strictly DESCENDING
 * total stake as pub_fill decreases: fill 0x10+i, stake bonus (n-i). */
static int seed_validators(nodus_witness_t *w, int n) {
    for (int i = 0; i < n; i++) {
        dnac_validator_record_t v;
        init_validator(&v, (uint8_t)(0x10 + i), /*active_since=*/1,
                       DNAC_SELF_STAKE_AMOUNT,
                       /*external=*/(uint64_t)(n - i) * 1000000ULL,
                       DNAC_VALIDATOR_ACTIVE);
        if (nodus_validator_insert(w, &v) != 0) return -1;
    }
    char sql[128];
    snprintf(sql, sizeof(sql),
             "UPDATE validator_stats SET value = %d WHERE key = 'active_count'",
             n);
    return exec_sql(w, sql);
}

static int stats_active_count(nodus_witness_t *w) {
    int c = -1;
    if (nodus_validator_active_count(w, &c) != 0) return -1;
    return c;
}

/* ── 1. commit_next ─────────────────────────────────────────────────── */

static int test_commit_next(void) {
    fixture_t fx;
    CHECK(fx_open(&fx, 0xB1) == 0, "open");
    CHECK(insert_block_row(fx.w, LOOKBACK_THIS, 0xAA) == 0, "block this");
    CHECK(insert_block_row(fx.w, LOOKBACK_NEXT, 0xBB) == 0, "block next");
    CHECK(seed_validators(fx.w, 9) == 0, "seed 9");

    /* No governance row → the default target is DNAC_COMMITTEE_SIZE, so
     * 9 candidates yield a 7-seat set. */
    CHECK(nodus_witness_vset_commit_next(fx.w, B_HEIGHT) == 0, "commit_next");

    dna_vset_snapshot_t *snap = NULL;
    CHECK(nodus_witness_vset_get(fx.w, B_HEIGHT + E_LEN, &snap, NULL) == 0,
          "snapshot(next) missing");
    CHECK(snap->epoch == B_HEIGHT + E_LEN, "snapshot keyed on next epoch");
    CHECK(snap->active_count == DNAC_COMMITTEE_SIZE,
          "default target is not DNAC_COMMITTEE_SIZE");
    CHECK(snap->selection_ruleset == DNA_VSET_RULESET_TOPN_V1, "ruleset");

    /* Ranked by total stake DESC: 0x10 (bonus 9) first, 0x16 (bonus 3)
     * last of the seven; 0x17/0x18 are cut. */
    for (uint16_t i = 0; i < snap->active_count; i++) {
        uint8_t want[DNAC_PUBKEY_SIZE];
        memset(want, (uint8_t)(0x10 + i), sizeof(want));
        CHECK(memcmp(snap->entries[i].pubkey, want, DNAC_PUBKEY_SIZE) == 0,
              "snapshot rank order is not stake DESC");
        CHECK(snap->entries[i].self_bond == DNAC_SELF_STAKE_AMOUNT,
              "self_bond is not the validator's own bond");
    }
    dna_vset_free(&snap);

    /* Idempotent: same state → byte-identical snapshot → insert returns
     * 0 on the identity path, so the wrapper returns 0. */
    CHECK(nodus_witness_vset_commit_next(fx.w, B_HEIGHT) == 0,
          "second commit_next is not idempotent");

    fx_close(&fx);
    return 0;
}

/* A DIFFERENT snapshot already stored for the target epoch must make the
 * wrapper fail (the -2 conflict is fatal, never an overwrite). */
static int test_commit_next_conflict(void) {
    fixture_t fx;
    CHECK(fx_open(&fx, 0xB2) == 0, "open");
    CHECK(insert_block_row(fx.w, LOOKBACK_THIS, 0xAA) == 0, "block this");
    CHECK(insert_block_row(fx.w, LOOKBACK_NEXT, 0xBB) == 0, "block next");
    CHECK(seed_validators(fx.w, 9) == 0, "seed 9");

    /* Pre-store a VALID but 2-seat snapshot for the target epoch. */
    uint8_t *blob = NULL, hash[64];
    size_t blob_len = 0;
    CHECK(nodus_witness_vset_build_for_epoch(fx.w, B_HEIGHT + E_LEN, 2,
                                             NULL, &blob, &blob_len,
                                             hash) == 0, "build 2-seat");
    CHECK(nodus_witness_vset_insert(fx.w, B_HEIGHT + E_LEN, blob, blob_len,
                                    hash, B_HEIGHT) == 0, "pre-insert");
    free(blob);

    /* commit_next would produce a 7-seat snapshot for the same epoch.
     * Two different validator sets claiming one epoch is a
     * validator_set_root divergence — fatal. */
    CHECK(nodus_witness_vset_commit_next(fx.w, B_HEIGHT) == -1,
          "conflicting snapshot was not fatal");

    fx_close(&fx);
    return 0;
}

/* ── 2. Boundary flips ──────────────────────────────────────────────── */

static int test_flips(void) {
    fixture_t fx;
    CHECK(fx_open(&fx, 0xB3) == 0, "open");
    CHECK(insert_block_row(fx.w, LOOKBACK_THIS, 0xAA) == 0, "block this");
    CHECK(seed_validators(fx.w, 9) == 0, "seed 9");
    CHECK(stats_active_count(fx.w) == 9, "stats seeded");

    /* Freeze THIS epoch's 7-seat set. */
    uint8_t *blob = NULL, hash[64];
    size_t blob_len = 0;
    CHECK(nodus_witness_vset_build_for_epoch(fx.w, B_HEIGHT,
                                             DNAC_COMMITTEE_SIZE, NULL,
                                             &blob, &blob_len, hash) == 0,
          "build this-epoch snapshot");
    CHECK(nodus_witness_vset_insert(fx.w, B_HEIGHT, blob, blob_len, hash,
                                    B_HEIGHT - E_LEN) == 0, "insert");
    free(blob);

    CHECK(nodus_witness_vset_apply_boundary_flips(fx.w, B_HEIGHT) == 0,
          "flips failed");

    /* Top 7 stay ACTIVE, the 2 cut become ELIGIBLE. */
    for (int i = 0; i < 7; i++) {
        CHECK(status_of(fx.w, (uint8_t)(0x10 + i)) == DNAC_VALIDATOR_ACTIVE,
              "seated validator is not ACTIVE");
    }
    CHECK(status_of(fx.w, 0x17) == DNAC_VALIDATOR_ELIGIBLE,
          "unseated validator is not ELIGIBLE");
    CHECK(status_of(fx.w, 0x18) == DNAC_VALIDATOR_ELIGIBLE,
          "unseated validator is not ELIGIBLE");

    /* Bonds are untouched by a membership flip. */
    for (int i = 0; i < 9; i++) {
        CHECK(self_stake_of(fx.w, (uint8_t)(0x10 + i)) ==
              DNAC_SELF_STAKE_AMOUNT, "flip moved a bond");
    }
    /* validator_stats.active_count counts BONDED validators (bumped by
     * apply_stake, decremented on retirement). A 0↔4 flip must not move
     * it — both statuses are bonded. */
    CHECK(stats_active_count(fx.w) == 9,
          "flips changed validator_stats.active_count");

    /* Idempotent: the flips are absolute assignments, so a replay of the
     * same boundary against the same state is a no-op. */
    CHECK(nodus_witness_vset_apply_boundary_flips(fx.w, B_HEIGHT) == 0,
          "re-run failed");
    CHECK(status_of(fx.w, 0x10) == DNAC_VALIDATOR_ACTIVE, "re-run seated");
    CHECK(status_of(fx.w, 0x18) == DNAC_VALIDATOR_ELIGIBLE, "re-run unseated");

    /* An ELIGIBLE validator is still a CANDIDATE: raise 0x18's stake past
     * everyone and it must re-enter the next selection. This is the
     * property nodus_validator_top_n's status IN (ACTIVE, ELIGIBLE)
     * carries — an ACTIVE-only filter would make ELIGIBLE absorbing. */
    {
        char sql[192];
        snprintf(sql, sizeof(sql),
                 "UPDATE validators SET external_delegated = 99000000000, "
                 "total_delegated = 99000000000 WHERE status = %d",
                 (int)DNAC_VALIDATOR_ELIGIBLE);
        CHECK(exec_sql(fx.w, sql) == 0, "raise eligible stake");
    }
    {
        nodus_committee_member_t *m =
            calloc((size_t)DNAC_MAX_ACTIVE_VALIDATORS, sizeof(*m));
        CHECK(m != NULL, "alloc");
        int c = 0;
        CHECK(nodus_committee_compute_for_epoch(fx.w, B_HEIGHT, m,
                                                DNAC_MAX_ACTIVE_VALIDATORS,
                                                &c) == 0, "recompute");
        CHECK(c == DNAC_COMMITTEE_SIZE, "recompute size");
        uint8_t want[DNAC_PUBKEY_SIZE];
        memset(want, 0x17, sizeof(want));
        int found = 0;
        for (int i = 0; i < c; i++)
            if (memcmp(m[i].pubkey, want, DNAC_PUBKEY_SIZE) == 0) found = 1;
        CHECK(found, "an ELIGIBLE validator could not be re-selected");
        free(m);
    }

    fx_close(&fx);
    return 0;
}

/* Missing snapshot → NO-OP, rc 0, no status changes. */
static int test_flips_missing_snapshot(void) {
    fixture_t fx;
    CHECK(fx_open(&fx, 0xB4) == 0, "open");
    CHECK(insert_block_row(fx.w, LOOKBACK_THIS, 0xAA) == 0, "block this");
    CHECK(seed_validators(fx.w, 9) == 0, "seed 9");

    CHECK(nodus_witness_vset_apply_boundary_flips(fx.w, B_HEIGHT) == 0,
          "missing snapshot is not a no-op");
    for (int i = 0; i < 9; i++) {
        CHECK(status_of(fx.w, (uint8_t)(0x10 + i)) == DNAC_VALIDATOR_ACTIVE,
              "no-op path changed a status");
    }

    fx_close(&fx);
    return 0;
}

/* THE SNAPSHOT IS THE AUTHORITY (ORCHESTRATOR integration decision):
 * membership for an epoch comes from the set frozen one epoch earlier,
 * NEVER from a flip-time recomputation. Constructed by storing a valid
 * snapshot and then changing the validator table so a live ranking WOULD
 * differ — the flips must still apply the frozen set, demoting the
 * now-higher-ranked intruder to ELIGIBLE. (An earlier draft made this
 * case fail the block via a recompute cross-check; that was a reachable
 * deterministic HALT — one mid-epoch UNSTAKE/DELEGATE was enough — and
 * was removed. See nodus_witness_vset.c "THE SNAPSHOT IS THE AUTHORITY".) */
static int test_flips_snapshot_is_authority(void) {
    fixture_t fx;
    CHECK(fx_open(&fx, 0xB5) == 0, "open");
    CHECK(insert_block_row(fx.w, LOOKBACK_THIS, 0xAA) == 0, "block this");
    CHECK(seed_validators(fx.w, 9) == 0, "seed 9");

    uint8_t *blob = NULL, hash[64];
    size_t blob_len = 0;
    CHECK(nodus_witness_vset_build_for_epoch(fx.w, B_HEIGHT,
                                             DNAC_COMMITTEE_SIZE, NULL,
                                             &blob, &blob_len, hash) == 0,
          "build");
    CHECK(nodus_witness_vset_insert(fx.w, B_HEIGHT, blob, blob_len, hash,
                                    B_HEIGHT - E_LEN) == 0, "insert");
    free(blob);

    /* A tenured validator with more stake than anyone in the frozen set
     * now exists — a live ranking would seat it. The frozen set must win. */
    {
        dnac_validator_record_t v;
        init_validator(&v, 0x99, /*active_since=*/1,
                       DNAC_SELF_STAKE_AMOUNT,
                       /*external=*/500000000000ULL,
                       DNAC_VALIDATOR_ACTIVE);
        CHECK(nodus_validator_insert(fx.w, &v) == 0, "insert intruder");
    }

    CHECK(nodus_witness_vset_apply_boundary_flips(fx.w, B_HEIGHT) == 0,
          "flips must apply the frozen snapshot, not recompute");
    /* The intruder outranks everyone but is NOT in the frozen set →
     * ELIGIBLE; the frozen top-7 (0x10..0x16, stakes descend with the
     * fill byte) stay ACTIVE; 0x18 was outside the frozen 7 → ELIGIBLE. */
    CHECK(status_of(fx.w, 0x99) == DNAC_VALIDATOR_ELIGIBLE,
          "intruder was seated by a live ranking — authority violated");
    CHECK(status_of(fx.w, 0x10) == DNAC_VALIDATOR_ACTIVE,
          "frozen member lost its seat to a live ranking");
    CHECK(status_of(fx.w, 0x18) == DNAC_VALIDATOR_ELIGIBLE,
          "validator outside the frozen set kept a seat");

    /* The VOTING committee consumes the same authority: get_for_block on
     * a height inside this epoch must serve the frozen snapshot, so the
     * higher-ranked intruder does NOT appear and self_stake is the real
     * bond (served from the snapshot's self_bond field). */
    {
        nodus_committee_member_t *m =
            calloc((size_t)DNAC_MAX_ACTIVE_VALIDATORS, sizeof(*m));
        CHECK(m != NULL, "alloc members");
        int count = 0;
        CHECK(nodus_committee_get_for_block(fx.w, B_HEIGHT + 3, m,
                                            DNAC_MAX_ACTIVE_VALIDATORS,
                                            &count) == 0,
              "get_for_block failed on a snapshot-bearing epoch");
        CHECK(count == 7, "committee size != frozen snapshot size");
        for (int i = 0; i < count; i++) {
            CHECK(m[i].pubkey[0] != 0x99,
                  "live-ranked intruder served as committee member");
            CHECK(m[i].self_stake == DNAC_SELF_STAKE_AMOUNT,
                  "snapshot-served member lost its real bond");
        }
        /* Cache-hit path must agree with the miss path byte-for-byte. */
        nodus_committee_member_t *m2 =
            calloc((size_t)DNAC_MAX_ACTIVE_VALIDATORS, sizeof(*m2));
        CHECK(m2 != NULL, "alloc members 2");
        int count2 = 0;
        CHECK(nodus_committee_get_for_block(fx.w, B_HEIGHT + 4, m2,
                                            DNAC_MAX_ACTIVE_VALIDATORS,
                                            &count2) == 0, "cache hit");
        CHECK(count2 == count, "hit/miss count mismatch");
        CHECK(memcmp(m, m2,
                     (size_t)count * sizeof(*m)) == 0,
              "cache hit differs from cache miss");
        free(m);
        free(m2);
    }

    fx_close(&fx);
    return 0;
}

/* ── 3. Dynamic sizing ──────────────────────────────────────────────── */

static int test_target_sizing(void) {
    fixture_t fx;
    CHECK(fx_open(&fx, 0xB6) == 0, "open");
    CHECK(insert_block_row(fx.w, LOOKBACK_THIS, 0xAA) == 0, "block this");
    CHECK(insert_block_row(fx.w, LOOKBACK_NEXT, 0xBB) == 0, "block next");
    CHECK(seed_validators(fx.w, 9) == 0, "seed 9");

    /* GROW: a committed override effective at or before the NEXT epoch's
     * start height widens the set to 9. */
    CHECK(set_target_active(fx.w, 9, B_HEIGHT + E_LEN) == 0, "grow row");
    CHECK(nodus_witness_vset_commit_next(fx.w, B_HEIGHT) == 0, "commit 9");
    {
        dna_vset_snapshot_t *snap = NULL;
        CHECK(nodus_witness_vset_get(fx.w, B_HEIGHT + E_LEN, &snap,
                                     NULL) == 0, "get 9");
        CHECK(snap->active_count == 9, "target growth not honoured");
        dna_vset_free(&snap);
    }

    /* SHRINK back to 7 for a LATER epoch. Keyed on that epoch's start
     * height, so the already-frozen 9-seat epoch is untouched. */
    uint64_t b2 = B_HEIGHT + E_LEN;             /* next boundary        */
    CHECK(insert_block_row(fx.w, b2 - 1ULL, 0xCC) == 0, "block b2");
    CHECK(set_target_active(fx.w, 7, b2 + E_LEN) == 0, "shrink row");
    CHECK(nodus_witness_vset_commit_next(fx.w, b2) == 0, "commit 7");
    {
        dna_vset_snapshot_t *snap = NULL;
        CHECK(nodus_witness_vset_get(fx.w, b2 + E_LEN, &snap, NULL) == 0,
              "get 7");
        CHECK(snap->active_count == 7, "target shrink not honoured");
        dna_vset_free(&snap);
    }

    fx_close(&fx);
    return 0;
}

/* A tenure-unmet ("PENDING") validator is excluded even when the target
 * has room, and extra self-bond changes the ranking. */
static int test_pending_and_extra_bond(void) {
    fixture_t fx;
    CHECK(fx_open(&fx, 0xB7) == 0, "open");
    CHECK(insert_block_row(fx.w, LOOKBACK_THIS, 0xAA) == 0, "block this");
    CHECK(seed_validators(fx.w, 5) == 0, "seed 5");

    /* Target 9 — more room than there are candidates. */
    CHECK(set_target_active(fx.w, 9, 0) == 0, "target row");

    /* PENDING: stored status ACTIVE but active_since_block so recent that
     * active_since + MIN_TENURE > lookback. Derived, not a stored value. */
    {
        dnac_validator_record_t v;
        init_validator(&v, 0x77, /*active_since=*/LOOKBACK_THIS,
                       DNAC_SELF_STAKE_AMOUNT,
                       /*external=*/900000000000ULL,   /* richest of all */
                       DNAC_VALIDATOR_ACTIVE);
        CHECK(nodus_validator_insert(fx.w, &v) == 0, "insert pending");
    }

    nodus_committee_member_t *m =
        calloc((size_t)DNAC_MAX_ACTIVE_VALIDATORS, sizeof(*m));
    CHECK(m != NULL, "alloc");
    int c = 0;
    CHECK(nodus_committee_compute_for_epoch(fx.w, B_HEIGHT, m,
                                            DNAC_MAX_ACTIVE_VALIDATORS,
                                            &c) == 0, "compute");
    CHECK(c == 5, "tenure-unmet validator entered the set");
    {
        uint8_t pending[DNAC_PUBKEY_SIZE];
        memset(pending, 0x77, sizeof(pending));
        for (int i = 0; i < c; i++) {
            CHECK(memcmp(m[i].pubkey, pending, DNAC_PUBKEY_SIZE) != 0,
                  "PENDING validator was selected");
        }
    }

    /* EXTRA SELF-BOND: the lowest-ranked seeded validator (0x14, external
     * bonus 1) overtakes the top one (0x10, bonus 5) purely on own bond.
     * Ranking is (self_stake + external_delegated), so a larger bond is
     * rank-relevant — the S3 O-3 decision. */
    {
        char sql[256];
        snprintf(sql, sizeof(sql),
                 "UPDATE validators SET self_stake = %llu WHERE status = %d "
                 "AND external_delegated = 1000000",
                 (unsigned long long)(DNAC_SELF_STAKE_AMOUNT + 50000000000ULL),
                 (int)DNAC_VALIDATOR_ACTIVE);
        CHECK(exec_sql(fx.w, sql) == 0, "extra bond");
    }
    c = 0;
    CHECK(nodus_committee_compute_for_epoch(fx.w, B_HEIGHT, m,
                                            DNAC_MAX_ACTIVE_VALIDATORS,
                                            &c) == 0, "recompute");
    CHECK(c == 5, "count after extra bond");
    {
        uint8_t want[DNAC_PUBKEY_SIZE];
        memset(want, 0x14, sizeof(want));
        CHECK(memcmp(m[0].pubkey, want, DNAC_PUBKEY_SIZE) == 0,
              "extra self-bond did not change the ranking");
        CHECK(m[0].self_stake == DNAC_SELF_STAKE_AMOUNT + 50000000000ULL,
              "member self_stake is not the real bond");
    }
    free(m);

    /* A below-minimum bond is UNREACHABLE, so it is documented rather
     * than tested: nodus_validator_top_n has no bond floor, but the only
     * writer of a validator row on the consensus path is apply_stake
     * (nodus_witness_bft.c), which now rejects any STAKE whose derived
     * bond is < DNAC_SELF_STAKE_AMOUNT, and the genesis seeder writes
     * exactly DNAC_SELF_STAKE_AMOUNT. No committed path can create one. */

    fx_close(&fx);
    return 0;
}

/* ── 4. One validator, one vote ─────────────────────────────────────── */

static int test_one_validator_one_vote(void) {
    nodus_witness_bft_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    nodus_witness_bft_config_init(&cfg, 9);
    CHECK(cfg.quorum == 7, "quorum(9) != 7");
    CHECK(cfg.n_witnesses == 9, "n_witnesses(9) != 9");
    CHECK(cfg.quorum == dna_bft_quorum(9), "witness quorum != shared formula");

    /* The config is a function of the COUNT alone — there is no stake
     * input to derive it from. nodus_witness_bft_config_init's only
     * argument is `n`, so a stake-weighted quorum is not expressible
     * without changing the signature. */
    nodus_witness_bft_config_t cfg7;
    memset(&cfg7, 0, sizeof(cfg7));
    nodus_witness_bft_config_init(&cfg7, DNAC_COMMITTEE_SIZE);
    CHECK(cfg7.quorum == 5, "live cluster quorum moved");
    return 0;
}

/* ── 5. Insertion-order independence ────────────────────────────────── */

static int test_insertion_order_independence(void) {
    uint8_t hash_fwd[64], hash_rev[64];
    size_t len_fwd = 0, len_rev = 0;
    uint8_t *blob_fwd = NULL, *blob_rev = NULL;

    {
        fixture_t fx;
        CHECK(fx_open(&fx, 0xB8) == 0, "open fwd");
        CHECK(insert_block_row(fx.w, LOOKBACK_THIS, 0xAA) == 0, "block");
        for (int i = 0; i < 9; i++) {
            dnac_validator_record_t v;
            init_validator(&v, (uint8_t)(0x10 + i), 1,
                           DNAC_SELF_STAKE_AMOUNT,
                           (uint64_t)(9 - i) * 1000000ULL,
                           DNAC_VALIDATOR_ACTIVE);
            CHECK(nodus_validator_insert(fx.w, &v) == 0, "insert fwd");
        }
        CHECK(nodus_witness_vset_build_for_epoch(fx.w, B_HEIGHT,
                                                 DNAC_COMMITTEE_SIZE, NULL,
                                                 &blob_fwd, &len_fwd,
                                                 hash_fwd) == 0, "build fwd");
        fx_close(&fx);
    }
    {
        fixture_t fx;
        CHECK(fx_open(&fx, 0xB9) == 0, "open rev");
        CHECK(insert_block_row(fx.w, LOOKBACK_THIS, 0xAA) == 0, "block");
        for (int i = 8; i >= 0; i--) {   /* REVERSE insertion order */
            dnac_validator_record_t v;
            init_validator(&v, (uint8_t)(0x10 + i), 1,
                           DNAC_SELF_STAKE_AMOUNT,
                           (uint64_t)(9 - i) * 1000000ULL,
                           DNAC_VALIDATOR_ACTIVE);
            CHECK(nodus_validator_insert(fx.w, &v) == 0, "insert rev");
        }
        CHECK(nodus_witness_vset_build_for_epoch(fx.w, B_HEIGHT,
                                                 DNAC_COMMITTEE_SIZE, NULL,
                                                 &blob_rev, &len_rev,
                                                 hash_rev) == 0, "build rev");
        fx_close(&fx);
    }

    /* The DB's ORDER BY (self_stake + external_delegated) DESC, pubkey ASC
     * plus the state-seeded tiebreak makes the result a function of the
     * SET, not of the write order. Two nodes that learned the same
     * validators in different orders MUST commit the same snapshot. */
    CHECK(len_fwd == len_rev, "snapshot length depends on insertion order");
    CHECK(blob_fwd && blob_rev, "blobs");
    CHECK(memcmp(blob_fwd, blob_rev, len_fwd) == 0,
          "snapshot BYTES depend on insertion order");
    CHECK(memcmp(hash_fwd, hash_rev, 64) == 0,
          "snapshot HASH depends on insertion order");
    free(blob_fwd);
    free(blob_rev);
    return 0;
}

/* ── 6. Fault injection ─────────────────────────────────────────────── */

static int test_db_fault_fails_closed(void) {
    fixture_t fx;
    CHECK(fx_open(&fx, 0xBA) == 0, "open");
    CHECK(insert_block_row(fx.w, LOOKBACK_THIS, 0xAA) == 0, "block this");
    CHECK(insert_block_row(fx.w, LOOKBACK_NEXT, 0xBB) == 0, "block next");
    CHECK(seed_validators(fx.w, 9) == 0, "seed 9");

    /* Storage gone → commit_next must FAIL, never silently skip the
     * commitment. A missing snapshot is indistinguishable from a
     * pre-S3 epoch at the flip site, so a swallowed persist error would
     * turn into a silent membership no-op one epoch later. */
    CHECK(exec_sql(fx.w, "DROP TABLE validator_set_snapshots") == 0, "drop");
    CHECK(nodus_witness_vset_commit_next(fx.w, B_HEIGHT) == -1,
          "commit_next did not fail on a missing table");

    /* The read side fails closed too. */
    dna_vset_snapshot_t *snap = NULL;
    CHECK(nodus_witness_vset_get(fx.w, B_HEIGHT, &snap, NULL) == -1,
          "vset_get did not fail on a missing table");
    CHECK(snap == NULL, "failed get wrote an output");

    fx_close(&fx);
    return 0;
}

/* An empty validator table has NO snapshot — commit_next must fail
 * rather than commit "nobody may vote at this epoch". */
static int test_empty_set_is_a_fault(void) {
    fixture_t fx;
    CHECK(fx_open(&fx, 0xBB) == 0, "open");
    CHECK(insert_block_row(fx.w, LOOKBACK_NEXT, 0xBB) == 0, "block next");
    CHECK(nodus_witness_vset_commit_next(fx.w, B_HEIGHT) == -1,
          "empty committee produced a snapshot");
    fx_close(&fx);
    return 0;
}

int main(void) {
    if (test_commit_next() != 0)                 return 1;
    if (test_commit_next_conflict() != 0)        return 1;
    if (test_flips() != 0)                       return 1;
    if (test_flips_missing_snapshot() != 0)      return 1;
    if (test_flips_snapshot_is_authority() != 0) return 1;
    if (test_target_sizing() != 0)               return 1;
    if (test_pending_and_extra_bond() != 0)      return 1;
    if (test_one_validator_one_vote() != 0)      return 1;
    if (test_insertion_order_independence() != 0) return 1;
    if (test_db_fault_fails_closed() != 0)       return 1;
    if (test_empty_set_is_a_fault() != 0)        return 1;

    printf("test_vset_boundary: %d checks OK\n", g_checks);
    return g_fails == 0 ? 0 : 1;
}
