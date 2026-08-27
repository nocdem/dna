/**
 * @file tests/test_v2_active_max.c
 * @brief Ledger V2 O15F Task 1 — the successor active-set maximum (30).
 *
 * THE INVARIANT (D1): on a successor chain no `validator_set_snapshots`
 * row with active_count > NODUS_V2_ACTIVE_SET_MAX (30) can ever be
 * PERSISTED. The persisted snapshot is the SOLE committee authority
 * (nodus_committee_get_for_block serves it RAW), so the bound is enforced
 * at every WRITE / SEED / RESOLVE point, all fail-closed, and legacy
 * chains keep the 128 ceiling byte-identically. This test drives all of
 * them through the REAL production functions:
 *
 *   §1  target clamp  — commit_genesis on a successor with 31 candidates
 *                       and a chain_config TARGET=31 seeds a <=30 snapshot.
 *   §2  committee_target clamp — isolated via bootstrap_for_epoch
 *                       (max_entries=128 so nothing else caps it).
 *   §3  insert reject — a hand-encoded 31-entry snapshot is refused on a
 *                       successor, accepted on legacy; 30 accepted on both.
 *   §4  resolve reject — a 31-entry row (seeded as legacy) resolves to no
 *                       authority once the handle is a successor; 30
 *                       resolves n=30, quorum=21.
 *   §5  live serve    — a 20-entry successor snapshot serves 20 members
 *                       through get_for_block and yields quorum 14.
 *
 * O15J Faz 3 — §6 (seam terminal-set precondition) and §7 (seam carried
 * chain_config reconciliation) are GONE. They drove
 * nodus_witness_v2_seam_maybe_derive, the legacy→successor activation
 * seam, which this phase deletes: a V2 chain is now born directly from a
 * config, so there is no transplanted terminal set to bound and no
 * carried chain_config row to reconcile. The active-set maximum itself is
 * unaffected — §1-§5 still enforce it at every write / seed / resolve
 * point, which is where the invariant actually lives.
 *
 * Copyright (c) 2026 nocdem — SPDX-License-Identifier: MIT
 */

#define _DEFAULT_SOURCE   /* mkdtemp under -std=c11 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "witness/nodus_witness_v2_schema.h"
#include "nodus/nodus_chain_config.h"
#include "dnac/dnac.h"
#include "dnac/validator.h"
#include "dnac/vset_wire.h"
#include "dnac/ledger_ids.h"

static int g_fail = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                msg); \
        g_fail = 1; \
    } } while (0)
#define OK() do { if (g_fail) return 1; } while (0)

#define E ((uint64_t)DNAC_EPOCH_LENGTH)

/* ── plain-witness fixture ───────────────────────────────────────────── */

static nodus_witness_t *mk_witness(char dir[128], const char *tag) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    snprintf(dir, 128, "/tmp/test_v2_amax_%s_XXXXXX", tag);
    if (!mkdtemp(dir)) { free(w); return NULL; }
    snprintf(w->data_path, sizeof(w->data_path), "%s", dir);
    uint8_t cid16[16];
    memset(cid16, 0x6c, sizeof(cid16));
    if (nodus_witness_create_chain_db(w, cid16) != 0) { free(w); return NULL; }
    if (nodus_chain_config_db_migrate(w) != 0) {
        if (w->db) sqlite3_close(w->db);
        free(w);
        return NULL;
    }
    /* Every fresh handle must have a cold committee cache, or a stale
     * cached_committee_epoch_start of 0 (from calloc) would masquerade as
     * epoch-0 already resolved. */
    w->cached_committee_epoch_start = UINT64_MAX;
    return w;
}

static void free_witness(nodus_witness_t *w, const char *dir) {
    if (!w) return;
    if (w->db) { sqlite3_close(w->db); w->db = NULL; }
    free(w);
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    (void)system(cmd);
}

static int64_t q1(sqlite3 *db, const char *sql) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -999;
    int64_t v = (sqlite3_step(st) == SQLITE_ROW)
                    ? sqlite3_column_int64(st, 0) : -999;
    sqlite3_finalize(st);
    return v;
}

/* Insert `k` bonded (ACTIVE) validators with distinct synthetic pubkeys.
 * self_stake = 0 (the fixtures do not model stake; a bonded filler would
 * unbalance the CORE supply equation, which counts Σself_stake), and
 * active_since_block = 1 uses the genesis carve-out so every one is
 * constitutionally tenured for the bootstrap epoch. */
static int insert_validators(nodus_witness_t *w, int k, uint8_t tag) {
    for (int i = 0; i < k; i++) {
        dnac_validator_record_t v;
        memset(&v, 0, sizeof(v));
        v.pubkey[0] = (uint8_t)(i & 0xFF);
        v.pubkey[1] = (uint8_t)((i >> 8) & 0xFF);
        v.pubkey[2] = tag;                    /* keeps sets in §1..§7 apart */
        v.self_stake         = 0;
        v.status             = DNAC_VALIDATOR_ACTIVE;
        v.active_since_block = 1;
        memset(v.unstake_destination_fp, '5', DNAC_FINGERPRINT_SIZE - 1);
        v.unstake_destination_fp[DNAC_FINGERPRINT_SIZE - 1] = '\0';
        if (nodus_validator_insert(w, &v) != 0) return -1;
    }
    return 0;
}

/* Insert a chain_config_history TARGET_ACTIVE_COUNT override (effective
 * from height 0). */
static int insert_cc_target(nodus_witness_t *w, uint64_t value) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO chain_config_history (param_id, new_value, "
            "effective_block, commit_block, tx_hash, proposal_nonce, "
            "created_at_unix) VALUES (?1, ?2, 0, 0, zeroblob(64), 0, 0)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int  (st, 1, (int)DNAC_CFG_TARGET_ACTIVE_COUNT);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)value);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* Hand-encode a valid snapshot of `n` DISTINCT entries (the codec rejects
 * duplicated voter_id AND duplicated pubkey) and insert it. Returns the
 * nodus_witness_vset_insert() return code, or a negative setup error. */
static int seed_snapshot(nodus_witness_t *w, uint64_t epoch_start,
                         uint16_t n, uint64_t created_at) {
    dna_vset_snapshot_t *snap = dna_vset_alloc(n);
    if (!snap) return -90;
    /* MUST match epoch_start: vset_get cross-checks the blob's epoch and
     * reports a mismatch as CORRUPT (-1), which would mask the assertion. */
    snap->epoch             = epoch_start;
    snap->selection_ruleset = DNA_VSET_RULESET_TOPN_V1;
    memset(snap->sortition_seed, 0, DNA_VSET_SEED_LEN);
    for (uint16_t i = 0; i < n; i++) {
        dna_vset_entry_t *e = &snap->entries[i];
        memset(e->voter_id, 0, sizeof(e->voter_id));
        e->voter_id[0] = (uint8_t)(i & 0xFF);
        e->voter_id[1] = (uint8_t)((i >> 8) & 0xFF);
        e->voter_id[2] = 0xAA;
        memset(e->pubkey, 0, sizeof(e->pubkey));
        e->pubkey[0] = (uint8_t)(i & 0xFF);
        e->pubkey[1] = (uint8_t)((i >> 8) & 0xFF);
        e->pubkey[2] = 0x55;
        e->total_stake    = 0;
        e->self_bond      = 0;
        e->commission_bps = 0;
    }
    size_t need = dna_vset_encoded_len(snap);
    if (need == 0) { dna_vset_free(&snap); return -91; }
    uint8_t *blob = malloc(need);
    if (!blob) { dna_vset_free(&snap); return -92; }
    size_t written = 0;
    if (dna_vset_encode(snap, blob, need, &written) != 0) {
        free(blob); dna_vset_free(&snap); return -93;
    }
    uint8_t hash[DNA_VSET_HASH_LEN];
    if (dna_vset_hash_bytes(blob, written, hash) != 0) {
        free(blob); dna_vset_free(&snap); return -94;
    }
    int rc = nodus_witness_vset_insert(w, epoch_start, blob, written, hash,
                                       created_at);
    free(blob);
    dna_vset_free(&snap);
    return rc;
}

/* Read back a persisted snapshot's decoded active_count, -1 if absent or
 * unreadable. */
static int64_t snap_active_count(nodus_witness_t *w, uint64_t epoch_start) {
    dna_vset_snapshot_t *snap = NULL;
    int rc = nodus_witness_vset_get(w, epoch_start, &snap, NULL);
    if (rc != 0 || !snap) { dna_vset_free(&snap); return -1; }
    int64_t c = (int64_t)snap->active_count;
    dna_vset_free(&snap);
    return c;
}

/* ════════════════════════════════════════════════════════════════════ */

static int test_target_clamp(void) {
    printf("§1 target clamp via commit_genesis (31 candidates, TARGET=31)\n");
    char dir[128];
    nodus_witness_t *w = mk_witness(dir, "clamp");
    CHECK(w != NULL, "witness");
    if (!w) return 1;

    CHECK(insert_validators(w, 31, 0x11) == 0, "31 ACTIVE validators");
    CHECK(insert_cc_target(w, 31) == 0, "chain_config TARGET_ACTIVE_COUNT=31");

    /* A V2 chain seeds its genesis snapshots (epochs 0 and E) here; the
     * clamp must fire during seeding, which runs BEFORE the committed
     * genesis manifest this flag is normally derived from (D1#4).
     *
     * The flag is therefore SET DIRECTLY: this fixture is a bare chain
     * database, not a derived V2 chain, so production's role derivation
     * would (correctly) leave it false and the clamp under test would
     * never be reached. What is being exercised here is the clamp, not the
     * role derivation — nodus_witness_v2_gen.c's own tests assert that
     * flag against a real derived chain rather than assigning it. */
    w->v2_successor = 1;
    CHECK(nodus_witness_vset_commit_genesis(w, 1) == 0,
          "commit_genesis seeds epochs 0 and E on the successor");

    int64_t c0 = snap_active_count(w, 0);
    int64_t cE = snap_active_count(w, E);
    CHECK(c0 == 30,
          "epoch-0 seeded snapshot is clamped to 30 (not 31)");
    CHECK(cE == 30,
          "epoch-E seeded snapshot is clamped to 30 (not 31)");

    free_witness(w, dir);
    OK();
    printf("  ok: successor genesis seeding clamps target 31 -> 30\n");
    return 0;
}

static int test_committee_target_clamp(void) {
    printf("§2 committee_target clamp isolated via bootstrap_for_epoch\n");
    char dir[128];
    nodus_witness_t *w = mk_witness(dir, "cmt");
    CHECK(w != NULL, "witness");
    if (!w) return 1;

    CHECK(insert_validators(w, 31, 0x22) == 0, "31 ACTIVE validators");
    CHECK(insert_cc_target(w, 31) == 0, "chain_config TARGET_ACTIVE_COUNT=31");

    nodus_committee_member_t *m =
        calloc((size_t)DNAC_MAX_ACTIVE_VALIDATORS, sizeof(*m));
    CHECK(m != NULL, "member array");
    if (!m) { free_witness(w, dir); return 1; }

    /* max_entries = 128 so ONLY committee_target_for_epoch can cap it. */
    int count = -1;
    w->v2_successor = 0;
    CHECK(nodus_committee_bootstrap_for_epoch(
              w, 0, m, DNAC_MAX_ACTIVE_VALIDATORS, &count) == 0,
          "legacy bootstrap");
    CHECK(count == 31,
          "legacy: committee_target 31 honored, no successor clamp");

    count = -1;
    w->v2_successor = 1;
    CHECK(nodus_committee_bootstrap_for_epoch(
              w, 0, m, DNAC_MAX_ACTIVE_VALIDATORS, &count) == 0,
          "successor bootstrap");
    CHECK(count == 30,
          "successor: committee_target clamped 31 -> 30");

    free(m);
    free_witness(w, dir);
    OK();
    printf("  ok: legacy 31 / successor 30\n");
    return 0;
}

static int test_insert_reject(void) {
    printf("§3 insert reject on a successor for >30, off-by-one at 30\n");
    char dir[128];
    nodus_witness_t *w = mk_witness(dir, "ins");
    CHECK(w != NULL, "witness");
    if (!w) return 1;

    /* successor: a 31-entry snapshot is refused and NOT stored */
    w->v2_successor = 1;
    CHECK(seed_snapshot(w, 0, 31, 1) == -1,
          "successor rejects a 31-entry snapshot");
    CHECK(q1(w->db,
             "SELECT COUNT(*) FROM validator_set_snapshots "
             "WHERE epoch_start = 0") == 0,
          "no 31-entry row was stored");

    /* successor: a 30-entry snapshot is accepted (accept side) */
    CHECK(seed_snapshot(w, E, 30, 1) == 0,
          "successor accepts a 30-entry snapshot");
    CHECK(q1(w->db,
             "SELECT active_count FROM validator_set_snapshots "
             "WHERE epoch_start = ?") >= 0 ||
          snap_active_count(w, E) == 30, "30-entry row present");

    /* legacy: the same 31-entry snapshot is accepted (128 ceiling intact) */
    w->v2_successor = 0;
    CHECK(seed_snapshot(w, 2 * E, 31, 1) == 0,
          "legacy accepts a 31-entry snapshot (unchanged)");
    CHECK(snap_active_count(w, 2 * E) == 31, "legacy 31-entry row present");

    free_witness(w, dir);
    OK();
    printf("  ok: successor 31 rejected / 30 accepted / legacy 31 accepted\n");
    return 0;
}

static int test_resolve_reject(void) {
    printf("§4 resolver reject on a successor for >30, quorum at 30\n");
    char dir[128];
    nodus_witness_t *w = mk_witness(dir, "res");
    CHECK(w != NULL, "witness");
    if (!w) return 1;

    /* Seed a 31-entry row as LEGACY so the writer accepts it, then flip
     * the handle to a successor: the resolver must refuse it. */
    w->v2_successor = 0;
    CHECK(seed_snapshot(w, E, 31, 1) == 0, "seed 31-entry row as legacy");

    w->v2_successor = 1;
    {
        dna_vset_snapshot_t *s = NULL;
        uint32_t n = 0, q = 0;
        CHECK(nodus_witness_v2_epoch_authority_for_epoch(w, E, &s, &n, &q)
                  == -1,
              "successor resolver refuses a 31-entry snapshot");
        dna_vset_free(&s);
    }

    /* A 30-entry row resolves: n=30, quorum = dna_bft_quorum(30) = 21. */
    CHECK(seed_snapshot(w, 2 * E, 30, 1) == 0,
          "seed 30-entry row (successor accepts)");
    {
        dna_vset_snapshot_t *s = NULL;
        uint32_t n = 0, q = 0;
        CHECK(nodus_witness_v2_epoch_authority_for_epoch(w, 2 * E, &s, &n, &q)
                  == 0,
              "successor resolver resolves a 30-entry snapshot");
        CHECK(n == 30, "n = 30");
        CHECK(q == 21, "quorum = dna_bft_quorum(30) = 21");
        CHECK(q == dna_bft_quorum(30), "quorum literal matches the formula");
        dna_vset_free(&s);
    }

    free_witness(w, dir);
    OK();
    printf("  ok: 31 refused / 30 resolves n=30 quorum=21\n");
    return 0;
}

static int test_live_serve(void) {
    printf("§5 live get_for_block serves a 20-entry successor snapshot\n");
    char dir[128];
    nodus_witness_t *w = mk_witness(dir, "srv");
    CHECK(w != NULL, "witness");
    if (!w) return 1;

    w->v2_successor = 1;
    CHECK(seed_snapshot(w, 0, 20, 1) == 0, "seed 20-entry successor snapshot");
    w->cached_committee_epoch_start = UINT64_MAX;   /* cold cache */

    nodus_committee_member_t *m =
        calloc((size_t)DNAC_MAX_ACTIVE_VALIDATORS, sizeof(*m));
    CHECK(m != NULL, "member array");
    if (!m) { free_witness(w, dir); return 1; }

    int count = -1;
    CHECK(nodus_committee_get_for_block(
              w, 0, m, DNAC_MAX_ACTIVE_VALIDATORS, &count) == 0,
          "get_for_block serves the snapshot");
    CHECK(count == 20, "exactly 20 members served");
    free(m);

    CHECK(refresh_bft_config_from_committee(w, 0) == 0,
          "refresh_bft_config_from_committee");
    CHECK(w->bft_config.quorum == 14,
          "quorum = dna_bft_quorum(20) = 14");
    CHECK(w->bft_config.quorum == dna_bft_quorum(20),
          "quorum literal matches the formula");

    /* Invariant closure: the write reject (§3) guarantees no >30 row can
     * ever be present to serve here, so the raw serve is always <=30. */
    CHECK(seed_snapshot(w, 3 * E, 31, 1) == -1,
          "a >30 snapshot can never be inserted to be served");

    free_witness(w, dir);
    OK();
    printf("  ok: 20 served, quorum 14, >30 unserveable\n");
    return 0;
}

int main(void) {
    printf("=== Ledger V2 O15F Task 1 — successor active-set maximum 30 ===\n\n");

    /* Run every section (accumulate) so a failing run shows the FULL
     * failure set, not just the first — the vacuity guard for TDD. */
    int rc = 0;
    rc |= test_target_clamp();
    rc |= test_committee_target_clamp();
    rc |= test_insert_reject();
    rc |= test_resolve_reject();
    rc |= test_live_serve();

    if (rc || g_fail) {
        printf("\nSOME O15F TASK 1 TESTS FAILED\n");
        return 1;
    }
    printf("\nALL O15F TASK 1 TESTS PASSED\n");
    return 0;
}
